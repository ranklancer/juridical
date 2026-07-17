package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Log is an append-only, hash-chained audit log. The Phase-1 default backing
// store is a 0600 JSONL file on a path outside the web root; an in-memory log
// (Path == "") is used for tests. All appends are serialized.
type Log struct {
	mu   sync.Mutex
	path string
	seq  uint64
	prev string
	mem  []Record // retained when path == "" (in-memory mode)
	now  func() time.Time
}

// Open returns a Log backed by an append-only 0600 JSONL file at path,
// resuming seq/prev from the existing chain (which it verifies). An empty path
// yields an in-memory log.
func Open(path string) (*Log, error) {
	l := &Log{path: path, prev: GenesisPrevHash, now: time.Now}
	if path == "" {
		return l, nil
	}
	existing, err := readAll(path)
	if err != nil {
		return nil, err
	}
	if bad, err := Verify(existing); err != nil {
		return nil, errors.New("audit: refusing to open a tampered log at record " + itoa(bad) + ": " + err.Error())
	}
	if n := len(existing); n > 0 {
		l.seq = existing[n-1].Seq
		l.prev = existing[n-1].RecordHash
	}
	return l, nil
}

// Append finalizes r (seq, ts, redaction, chain links, record hash) and writes
// it. Params are redacted here so a caller cannot forget. It returns the
// written record.
func (l *Log) Append(r Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	r.Seq = l.seq
	if r.TS == "" {
		r.TS = l.now().UTC().Format(time.RFC3339)
	}
	r.ParamsRedacted = Redact(r.ParamsRedacted)
	r.PrevRecordHash = l.prev
	h, err := ComputeRecordHash(r)
	if err != nil {
		l.seq-- // roll back the counter on failure
		return Record{}, err
	}
	r.RecordHash = h

	if l.path == "" {
		l.mem = append(l.mem, r)
		l.prev = h
		return r, nil
	}
	if err := appendLine(l.path, r); err != nil {
		l.seq--
		return Record{}, err
	}
	l.prev = h
	return r, nil
}

// Records returns the current chain (in-memory copy or a re-read of the file).
func (l *Log) Records() ([]Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.path == "" {
		out := make([]Record, len(l.mem))
		copy(out, l.mem)
		return out, nil
	}
	return readAll(l.path)
}

func appendLine(path string, r Record) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- audit log path is operator-configured (config), never attacker-controlled input
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return err
	}
	// fsync the record to stable storage before reporting success: an audit
	// record that backs a mutation must be durable, not merely buffered in the
	// page cache where a crash could lose it.
	return f.Sync()
}

func readAll(path string) ([]Record, error) {
	f, err := os.Open(path) // #nosec G304 -- audit log path is operator-configured (config), never attacker-controlled input
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r Record
		// Strict decode: the audit chain is tamper-evident, so a record
		// carrying an unknown or renamed field is treated as corruption and
		// fails the load CLOSED (Open -> readAll -> Verify) rather than being
		// silently coerced. Every legitimate field is a tagged Record field,
		// so this never rejects a well-formed row. Missing fields are tolerated
		// (adding a new Record field stays read-compatible with older logs);
		// a renamed/removed field is deliberately treated as corruption — for a
		// tamper-evident log, drift IS tamper, and a schema change must ship a
		// migration rather than silently coercing history.
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("audit: refusing a malformed/unknown-field record (strict decode): %w", err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		p--
		b[p] = '-'
	}
	return string(b[p:])
}

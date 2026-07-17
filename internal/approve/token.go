package approve

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Token errors (FC4): a token missing / expired / reused / hash-mismatch is a
// reject, never an execution.
var (
	ErrTokenUnknown  = errors.New("approve: token unknown (FC4)")
	ErrTokenExpired  = errors.New("approve: token expired (FC4)")
	ErrTokenConsumed = errors.New("approve: token already consumed (FC4)")
	ErrHashMismatch  = errors.New("approve: token not bound to this plan hash (FC4, T3)")
	ErrEmptyPlanHash = errors.New("approve: cannot mint against an empty plan hash")
)

// tokenRecord is the server-side state for a minted token. The secret itself is
// never stored — only its SHA-256 — so a store compromise cannot present a
// token (the internal design spec §6.3).
type tokenRecord struct {
	hash          [32]byte
	planHash      string
	proposerKeyID string
	approver      string
	expiresAt     time.Time
	consumed      bool
}

// TokenStore mints, stores (hashed), and consumes one-time approval tokens.
// It is safe for concurrent use.
type TokenStore struct {
	mu  sync.Mutex
	rec map[[32]byte]*tokenRecord
	now func() time.Time
}

// NewTokenStore returns an empty in-memory token store.
func NewTokenStore() *TokenStore {
	return &TokenStore{rec: make(map[[32]byte]*tokenRecord), now: time.Now}
}

// Mint creates a 256-bit random secret bound to planHash, stores only its hash,
// and returns the secret (shown once). ttl sets the expiry (the internal design spec §6.3,
// default 300s is the caller's choice). SoD must already have been checked.
func (s *TokenStore) Mint(planHash, proposerKeyID, approver string, ttl time.Duration) (string, error) {
	if planHash == "" {
		return "", ErrEmptyPlanHash
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	h := sha256.Sum256(secret[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rec[h] = &tokenRecord{
		hash:          h,
		planHash:      planHash,
		proposerKeyID: proposerKeyID,
		approver:      approver,
		expiresAt:     s.now().Add(ttl),
	}
	return hex.EncodeToString(secret[:]), nil
}

// Consumed is the identity carried back from a successful Consume.
type Consumed struct {
	PlanHash      string
	ProposerKeyID string
	Approver      string
}

// Consume verifies the presented secret is known, unexpired, unconsumed, and
// bound to planHash, then marks it consumed (one-time, T4). Any failure returns
// an error and leaves nothing executed. A consumed token can never be reused.
func (s *TokenStore) Consume(secretHex, planHash string) (Consumed, error) {
	raw, err := hex.DecodeString(secretHex)
	if err != nil || len(raw) != 32 {
		return Consumed{}, ErrTokenUnknown
	}
	h := sha256.Sum256(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rec[h]
	if !ok {
		return Consumed{}, ErrTokenUnknown
	}
	if r.consumed {
		return Consumed{}, ErrTokenConsumed
	}
	if s.now().After(r.expiresAt) {
		return Consumed{}, ErrTokenExpired
	}
	// constant-time compare of the bound plan hash
	if subtle.ConstantTimeCompare([]byte(r.planHash), []byte(planHash)) != 1 {
		return Consumed{}, ErrHashMismatch
	}
	r.consumed = true
	return Consumed{PlanHash: r.planHash, ProposerKeyID: r.proposerKeyID, Approver: r.approver}, nil
}

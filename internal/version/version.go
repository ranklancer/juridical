// Package version exposes build metadata for the Juridical binary.
//
// The three variables are overridden at link time via -ldflags "-X ..."
// (see the Makefile and .goreleaser.yaml). They default to development
// placeholders so a plain `go build` still produces a runnable binary.
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version of the build (e.g. "0.1.0").
	Version = "0.0.0-dev"
	// Commit is the short git SHA the build was produced from.
	Commit = "none"
	// Date is the build timestamp (RFC3339, UTC).
	Date = "unknown"
)

// Info is the resolved build metadata.
type Info struct {
	Version string
	Commit  string
	Date    string
	Go      string
}

// Get returns the build metadata for this binary.
func Get() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
		Go:      runtime.Version(),
	}
}

// String renders the build metadata on a single line.
func (i Info) String() string {
	return fmt.Sprintf("juridical %s (commit %s, built %s, %s)",
		i.Version, i.Commit, i.Date, i.Go)
}

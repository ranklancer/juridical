// Command juridical is the entry point for the Juridical control plane.
//
// This founding scaffold ships no feature code: `main` resolves build
// metadata and prints version/usage. The Phase-1 subcommands (serve, action,
// plan, approve, audit) are declared in the usage text and implemented in
// later, independently reviewed pull requests per the internal design spec.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/juridical-docker/juridical/internal/version"
)

const usage = `juridical - blast-radius-bounded action executor with an approval gate and audit trail.

Usage:
  juridical <command> [flags]

Commands (Phase 1 - not yet implemented in this scaffold):
  serve      run the control-plane HTTP API
  action     inspect the registered action set
  plan       compute a blast-radius-bounded plan for an action
  approve    mint or verify an approval token for a plan
  audit      read the append-only, hash-chained audit log

Global flags:
  -version   print build metadata and exit
  -help      print this message and exit
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("juridical", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print build metadata and exit")
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintln(stdout, version.Get().String())
		return 0
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}

	switch rest[0] {
	case "serve", "action", "plan", "approve", "audit":
		fmt.Fprintf(stderr, "juridical: %q is not implemented in this scaffold (Phase 1, see the internal design spec)\n", rest[0])
		return 3
	case "help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "juridical: unknown command %q\n\n%s", rest[0], usage)
		return 2
	}
}

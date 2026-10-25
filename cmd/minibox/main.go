// Command minibox is a small rootless Linux container runtime.
//
// The CLI is a thin dispatcher: each subcommand parses its own flags and hands
// off to an internal/ package. Keeping main free of OS logic makes the
// commands easy to test and keeps each OS concept in one place.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is overridden at build time by the Makefile via -ldflags.
var version = "dev"

const usage = `minibox: a rootless Linux container runtime

Usage:
  minibox run <rootfs> <cmd> [args...]      run a command in a container
  minibox profile <rootfs> <cmd> [args...]  trace a command and write a policy
  minibox version                           print version
  minibox help                              show this help
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches to a subcommand and returns the process exit code. It takes
// its arguments and output streams as parameters so tests can call it directly.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "minibox %s\n", version)
		return 0
	case "run":
		return notImplemented(stderr, "run", 1)
	case "profile":
		return notImplemented(stderr, "profile", 5)
	default:
		fmt.Fprintf(stderr, "minibox: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

// notImplemented is a placeholder so the CLI shape is fixed from day one;
// each phase replaces one of these with a real implementation.
func notImplemented(stderr io.Writer, cmd string, phase int) int {
	fmt.Fprintf(stderr, "minibox: %q is not implemented yet (Phase %d)\n", cmd, phase)
	return 1
}

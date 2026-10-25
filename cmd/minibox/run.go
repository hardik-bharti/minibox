package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/hardik-bharti/minibox/internal/container"
)

// cmdRun implements `minibox run [flags] <rootfs> <cmd> [args...]`.
//
// Go's flag package stops at the first non-flag argument, so flags must come
// before <rootfs>. That is what we want: in `minibox run img ls -l`, the -l
// belongs to ls, not to us.
func cmdRun(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hostname := fs.String("hostname", "", "container hostname (default: container ID)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: minibox run [flags] <rootfs> <cmd> [args...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 2 {
		fs.Usage()
		return 2
	}

	stateRoot, err := container.DefaultStateRoot()
	if err != nil {
		return fail(stderr, err)
	}
	cfg, err := container.NewConfig(fs.Arg(0), fs.Args()[1:], *hostname, stateRoot)
	if err != nil {
		return fail(stderr, err)
	}
	code, err := container.Run(cfg)
	if err != nil {
		return fail(stderr, err)
	}
	return code
}

// cmdInit is the hidden entry point for the re-executed child process; see
// container.Init. It only returns if setup failed, since on success the
// process is replaced by the user's command.
func cmdInit(stderr io.Writer) int {
	err := container.Init()
	fmt.Fprintf(stderr, "minibox: container init: %v\n", err)
	// 127 (not 1) so a setup failure can be told apart from a command that
	// merely exited with status 1. Shells use 127 for "command not found".
	return 127
}

func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "minibox: %v\n", err)
	return 1
}

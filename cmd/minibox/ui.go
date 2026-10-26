package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hardik-bharti/minibox/internal/ui"
)

// cmdUI implements `minibox ui`: serve the demo dashboard until Ctrl-C.
func cmdUI(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("ui", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:7070", "listen address; keep it on loopback and reach it through an SSH tunnel")
	image := fs.String("image", "images/alpine", "image for the demos")
	bench := fs.String("bench-image", "images/bench", "image with python3 (optional; enables the Python workload)")
	probe := fs.String("probe", "tests/attacks/bin/probe", "attack probe binary (optional; `make probe` builds it)")
	attackPolicy := fs.String("attack-policy", "results/policies/attack-probe.json", "policy used for the attack suite (generated if missing)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: minibox ui [flags]   (run from the repository root)")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}

	exe, err := os.Executable()
	if err != nil {
		return fail(stderr, err)
	}
	dir, err := os.Getwd()
	if err != nil {
		return fail(stderr, err)
	}
	state, err := os.MkdirTemp("", "minibox-ui-")
	if err != nil {
		return fail(stderr, err)
	}
	defer os.RemoveAll(state)

	srv, err := ui.New(ui.Config{Addr: *addr, Exe: exe, Dir: dir, Image: *image, BenchImage: *bench,
		Probe: *probe, AttackPolicy: *attackPolicy, StateDir: state})
	if err != nil {
		return fail(stderr, err)
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fail(stderr, err)
	}
	if host, _, _ := net.SplitHostPort(*addr); !net.ParseIP(host).IsLoopback() {
		fmt.Fprintf(stderr, "minibox ui: warning: listening on %s, not loopback. Anyone who can reach this address can start demos.\n", *addr)
	}
	fmt.Fprintf(stderr, "minibox ui: open http://%s  (Ctrl-C to quit)\n", ln.Addr())

	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Fprintln(stderr, "minibox ui: stopping")
		srv.Stop() // let the running demo clean up its container
		for i := 0; i < 50 && !srv.Idle(); i++ {
			time.Sleep(100 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		hs.Shutdown(ctx) // open event streams are cut off after a second
		hs.Close()
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail(stderr, err)
	}
	return 0
}

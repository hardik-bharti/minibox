package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// job is one run of an action. It may run several minibox commands (an
// attack under three configurations, for example), one after another.
type job struct {
	id     int
	panel  string
	action string
	s      *Server
	ctx    context.Context
	cancel context.CancelFunc
}

// runOpts adjusts one minibox command.
type runOpts struct {
	watch   bool          // stream cgroup meters (the command must set a limit or --stats)
	events  string        // tail this profiler event file (minibox profile --events)
	timeout time.Duration // default defaultTimeout
}

const (
	defaultTimeout = 60 * time.Second
	maxLineLen     = 400  // long lines are cut, so one runaway line can't flood the page
	maxLines       = 3000 // per command, kept for parsing results
)

// cmdResult is what a finished minibox command produced.
type cmdResult struct {
	Code int
	Out  []string // stdout lines
	Err  []string // stderr lines (minibox's own messages and the command's)
	Ms   int64
}

func (j *job) send(m Msg) {
	m.Job, m.Panel = j.id, j.panel
	j.s.hub.send(m)
}

// result sends structured data for the panel to draw.
func (j *job) result(data any) { j.send(Msg{Type: "result", Data: data}) }

// minibox runs `minibox <args...>` and streams its output to the page.
func (j *job) minibox(o runOpts, args ...string) (cmdResult, error) {
	if err := j.ctx.Err(); err != nil {
		return cmdResult{}, errStopped
	}
	timeout := o.timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(j.ctx, timeout)
	defer cancel()

	cmd := exec.Command(j.s.cfg.Exe, args...)
	cmd.Dir = j.s.cfg.Dir
	// A process group of its own: Ctrl-C in the terminal running
	// `minibox ui` reaches only the server, which then stops the job
	// cleanly, instead of hitting every container at once.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return cmdResult{}, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return cmdResult{}, err
	}

	j.send(Msg{Type: "cmd", Argv: append([]string{"minibox"}, args...)})
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return cmdResult{}, err
	}

	var res cmdResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); res.Out = j.stream(stdout, "out") }()
	go func() { defer wg.Done(); res.Err = j.stream(stderr, "err") }()

	// Side channels: meters and profiler events, until the command ends.
	side, stopSide := context.WithCancel(ctx)
	var sideWG sync.WaitGroup
	if o.watch {
		sideWG.Add(1)
		go func() {
			defer sideWG.Done()
			watchCgroup(side, cmd.Process.Pid, func(m Meter) { j.send(Msg{Type: "meter", Meter: &m}) })
		}()
	}
	if o.events != "" {
		sideWG.Add(1)
		go func() { defer sideWG.Done(); j.tailEvents(side, o.events) }()
	}

	exited := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stopGently(cmd.Process, exited)
		case <-exited:
		}
	}()

	wg.Wait() // output pipes close when minibox (and its container) exit
	waitErr := cmd.Wait()
	close(exited)
	stopSide()
	sideWG.Wait()

	res.Ms = time.Since(start).Milliseconds()
	res.Code = exitCode(waitErr)
	code := res.Code
	j.send(Msg{Type: "exit", Code: &code, Ms: res.Ms})
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return res, errors.New("timed out after " + timeout.String())
	}
	if j.ctx.Err() != nil {
		return res, errStopped
	}
	return res, nil
}

var errStopped = errors.New("stopped")

// stopGently asks minibox to stop the container the same way Ctrl-C does:
// minibox forwards the first signal and turns the second into SIGKILL,
// then cleans up its cgroup and state directory as usual. Killing minibox
// itself would skip that cleanup, so SIGKILL is only the last resort.
// exited is closed when the process has been reaped.
func stopGently(p *os.Process, exited <-chan struct{}) {
	for _, step := range []struct {
		sig  os.Signal
		wait time.Duration
	}{{syscall.SIGTERM, 300 * time.Millisecond}, {syscall.SIGTERM, 3 * time.Second}, {os.Kill, 0}} {
		p.Signal(step.sig)
		select {
		case <-exited:
			return
		case <-time.After(step.wait):
		}
	}
}

// stream forwards lines from r to the page and returns them.
func (j *job) stream(r io.Reader, name string) []string {
	var lines []string
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	for s.Scan() {
		line := s.Text()
		if len(line) > maxLineLen {
			line = line[:maxLineLen] + " …"
		}
		if len(lines) < maxLines {
			lines = append(lines, line)
			j.send(Msg{Type: "line", Stream: name, Text: line})
		}
	}
	return lines
}

// tailEvents follows the profiler's JSON-lines file and forwards each
// event. It keeps reading after ctx ends until the file is drained, so the
// last events (written just before minibox exits) are not lost.
func (j *job) tailEvents(ctx context.Context, path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	r := bufio.NewReader(f)
	var partial string
	for {
		line, err := r.ReadString('\n')
		partial += line
		if err == nil {
			var raw json.RawMessage
			if json.Unmarshal([]byte(partial), &raw) == nil {
				j.send(Msg{Type: "profile", Data: raw})
			}
			partial = ""
			continue
		}
		if ctx.Err() != nil {
			return // drained after the command ended
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// exitCode turns Wait's error into a shell-style exit code.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return -1
}

// stderrNotes returns minibox's own messages ("minibox: ..."), without the prefix.
func stderrNotes(lines []string) []string {
	var out []string
	for _, l := range lines {
		if rest, ok := strings.CutPrefix(l, "minibox: "); ok {
			out = append(out, rest)
		}
	}
	return out
}

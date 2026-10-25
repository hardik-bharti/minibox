package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// namespaces is the set of new namespaces each container gets.
//   - USER: we become "root" (UID 0) mapped to our real UID. This is what lets
//     an unprivileged user create the other namespaces and mount things.
//   - NS (mount): our overlay, /dev, /proc and pivot_root are invisible to the host.
//   - PID: the container sees only its own processes; its command is PID 1.
//   - UTS: the container can have its own hostname.
//   - IPC: separate System V IPC objects and POSIX message queues.
const namespaces = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
	syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC

// Run starts the container described by c, waits for it to exit and cleans
// up. It returns the command's exit code (128+N if it was killed by signal N,
// the shell convention).
func Run(c *Config) (int, error) {
	if err := createStateDir(c); err != nil {
		return 0, fmt.Errorf("create state dir: %w", err)
	}
	// The mounts need no cleanup from us: they exist only inside the
	// container's mount namespace, which the kernel destroys when its last
	// process exits. Only the directory on disk is left to remove.
	defer removeStateDir(c.StateDir)

	// Pdeathsig (below) is tied to the OS *thread* that started the child,
	// not to the process. Go may otherwise retire that thread while the
	// child is still running and kill it early, so we pin this goroutine to
	// its thread until the child has exited.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd, configW, err := startInit(c)
	if err != nil {
		return 0, err
	}
	if err := sendConfig(configW, c); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("send config: %w", err)
	}

	stop := forwardSignals(cmd.Process)
	defer stop()

	return exitCode(cmd.Wait())
}

// startInit re-executes our own binary as `minibox init` inside new
// namespaces. Go cannot run arbitrary code between fork and exec, so the
// usual way to set up a container in Go is to start a fresh copy of the
// program that is already inside the namespaces and finishes the setup
// there (see Init).
func startInit(c *Config) (*exec.Cmd, *os.File, error) {
	configR, configW, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer configR.Close() // the child holds its own copy after Start

	cmd := exec.Command("/proc/self/exe", "init")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{configR} // becomes fd 3 (configFD) in the child
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: namespaces,
		// Map container UID/GID 0 to our real UID/GID, and nothing else.
		// A single-ID mapping is the only kind an unprivileged process may
		// write without the setuid newuidmap helper.
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		// The kernel only accepts an unprivileged gid_map once setgroups is
		// disabled. Otherwise the container could drop supplementary groups
		// that the host uses to deny access to files.
		GidMappingsEnableSetgroups: false,
		// If minibox dies, kill the container instead of leaving it orphaned.
		Pdeathsig: syscall.SIGKILL,
	}

	if err := cmd.Start(); err != nil {
		configW.Close()
		return nil, nil, fmt.Errorf("start container: %w", err)
	}
	return cmd, configW, nil
}

func sendConfig(w *os.File, c *Config) error {
	defer w.Close() // EOF tells the child the config is complete
	return json.NewEncoder(w).Encode(c)
}

// forwardSignals relays termination signals to the container.
//
// The kernel protects a PID namespace's init (our command is PID 1 there)
// from signals that have no handler installed. So `sleep 100` as PID 1
// ignores SIGINT/SIGTERM, just like in Docker without --init. Rather than
// leave the user stuck, the second signal escalates to SIGKILL, which the
// kernel always delivers.
func forwardSignals(p *os.Process) (stop func()) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	done := make(chan struct{})

	go func() {
		forwarded := false
		for {
			select {
			case s := <-sigs:
				if forwarded {
					p.Kill()
					continue
				}
				p.Signal(s)
				forwarded = true
				fmt.Fprintf(os.Stderr, "minibox: forwarded %s to container; send it again to force kill\n",
					unix.SignalName(s.(syscall.Signal)))
			case <-done:
				return
			}
		}
	}()

	return func() {
		signal.Stop(sigs)
		close(done)
	}
}

// exitCode turns the result of Wait into a shell-style exit code.
func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		return 0, err
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal()), nil
	}
	return exitErr.ExitCode(), nil
}

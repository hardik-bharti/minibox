package profile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ptraceOptions:
//   - TRACESYSGOOD: syscall stops report SIGTRAP|0x80, so they can't be
//     confused with a real SIGTRAP.
//   - TRACECLONE/FORK/VFORK: new threads and child processes are traced
//     automatically, so we see the whole process tree.
//   - TRACEEXEC: a distinct stop on execve, which marks where minibox's
//     own setup ends and the user's program begins.
//   - EXITKILL: if minibox dies, the kernel kills every tracee, so an
//     untraced (unprofiled) container can't keep running.
const ptraceOptions = unix.PTRACE_O_TRACESYSGOOD | unix.PTRACE_O_TRACECLONE |
	unix.PTRACE_O_TRACEFORK | unix.PTRACE_O_TRACEVFORK |
	unix.PTRACE_O_TRACEEXEC | unix.PTRACE_O_EXITKILL

// syscallInfo is struct ptrace_syscall_info (PTRACE_GET_SYSCALL_INFO,
// Linux 5.3+). The kernel tells us whether a stop is a syscall entry or
// exit, so we don't have to track "in syscall" toggles per thread (a
// classic source of strace-style bugs around execve and signals).
type syscallInfo struct {
	Op    uint8 // ptraceSyscallInfo*
	_     [3]uint8
	Arch  uint32
	IP    uint64
	SP    uint64
	Union [7]uint64 // entry: nr, args[6]; exit: rval, is_error
}

const (
	opEntry = 1
	opExit  = 2
)

// event is one completed syscall, delivered to the recorder at exit.
type event struct {
	pid  int
	nr   int
	args [6]uint64
	ret  int64 // negative errno on failure
	// Captured at entry, while the arguments still describe the caller's
	// view (e.g. a path that unlink is about to remove).
	paths []pathArg
}

// handler is what the tracer reports to.
type handler interface {
	// onEntry may read the tracee's memory and returns the path
	// arguments to carry to onExit.
	onEntry(pid, nr int, args [6]uint64) []pathArg
	onExit(e event)
}

// tracer runs the ptrace loop for one container.
type tracer struct {
	h         handler
	recording bool           // set once the user's program has been exec'd
	pending   map[int]*event // syscall entered but not yet exited, by tid
	known     map[int]bool   // tids we have seen stop at least once
	alive     map[int]bool   // tids that have not exited yet
}

// trace drives ptrace until every traced task has exited and returns the
// wait status of the root task (the container's init). It must run on the
// OS thread that started the root task.
func (t *tracer) trace(root int) (syscall.WaitStatus, error) {
	t.pending = map[int]*event{}
	t.known = map[int]bool{root: true}
	t.alive = map[int]bool{root: true}

	// The child called PTRACE_TRACEME and is stopped at its first exec
	// (the re-exec of minibox as "init"). Set options, then let it run.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(root, &ws, unix.WALL, nil); err != nil {
		return 0, err
	}
	if !ws.Stopped() {
		return ws, fmt.Errorf("container exited before tracing started")
	}
	if err := unix.PtraceSetOptions(root, ptraceOptions); err != nil {
		return 0, fmt.Errorf("PTRACE_SETOPTIONS: %w", err)
	}
	if err := unix.PtraceSyscall(root, 0); err != nil {
		return 0, err
	}

	var rootStatus syscall.WaitStatus
	for len(t.alive) > 0 {
		// wait4(-1) reports any child, including slirp4netns. That one
		// only exits after the container (minibox stops it), and if it
		// died early we'd just reap it here: it isn't in t.alive, so
		// the bookkeeping below ignores it.
		pid, err := syscall.Wait4(-1, &ws, unix.WALL, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return rootStatus, fmt.Errorf("wait4: %w", err)
		}
		if ws.Exited() || ws.Signaled() {
			delete(t.alive, pid)
			delete(t.pending, pid)
			if pid == root {
				rootStatus = ws
			}
			continue
		}
		if !ws.Stopped() {
			continue
		}
		t.alive[pid] = true
		sig := t.handleStop(pid, ws)
		// ESRCH: the task was killed while stopped (e.g. the PID
		// namespace is being torn down). Its exit arrives next.
		if err := unix.PtraceSyscall(pid, sig); err != nil && !errors.Is(err, unix.ESRCH) {
			return rootStatus, fmt.Errorf("PTRACE_SYSCALL %d: %w", pid, err)
		}
	}
	return rootStatus, nil
}

// handleStop processes one ptrace stop and returns the signal to deliver
// when resuming (0 for none).
func (t *tracer) handleStop(pid int, ws syscall.WaitStatus) int {
	sig := ws.StopSignal()
	firstStop := !t.known[pid]
	t.known[pid] = true

	switch {
	case sig == syscall.SIGTRAP|0x80:
		t.handleSyscall(pid)
		return 0
	case sig == syscall.SIGTRAP && ws.TrapCause() != 0:
		if ws.TrapCause() == unix.PTRACE_EVENT_EXEC {
			// The first exec event is init exec'ing the user's command:
			// from here on, every syscall belongs to the application.
			t.recording = true
			// A non-leader thread that execs takes over the leader's
			// tid, so its old tid will never report again.
			if old, err := unix.PtraceGetEventMsg(pid); err == nil && int(old) != pid {
				delete(t.alive, int(old))
				delete(t.pending, int(old))
			}
		}
		// Clone/fork events: the new task is auto-attached and will
		// report its own first stop; nothing to do here.
		return 0
	case sig == syscall.SIGSTOP && firstStop:
		// Every auto-attached child starts with a SIGSTOP that is ptrace
		// bookkeeping, not a real signal: swallow it.
		return 0
	}
	// A genuine signal (e.g. SIGINT forwarded by minibox, SIGCHLD):
	// deliver it unchanged.
	return int(sig)
}

// handleSyscall reads the syscall info and reports entries and exits.
func (t *tracer) handleSyscall(pid int) {
	var info syscallInfo
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GET_SYSCALL_INFO,
		uintptr(pid), unsafe.Sizeof(info), uintptr(unsafe.Pointer(&info)), 0, 0)
	if errno != 0 || !t.recording {
		return
	}
	switch info.Op {
	case opEntry:
		e := &event{pid: pid, nr: int(info.Union[0])}
		copy(e.args[:], info.Union[1:7])
		e.paths = t.h.onEntry(pid, e.nr, e.args)
		t.pending[pid] = e
	case opExit:
		e, ok := t.pending[pid]
		if !ok {
			return // e.g. the exit half of the execve that started recording
		}
		delete(t.pending, pid)
		e.ret = int64(info.Union[0])
		t.h.onExit(*e)
	}
}

// readString reads a NUL-terminated string from the tracee's memory via
// /proc/<pid>/mem (much faster than PTRACE_PEEKDATA, one word at a time).
// We may open it because we are the tracer.
func readString(pid int, addr uint64) (string, error) {
	if addr == 0 {
		return "", errors.New("NULL pointer")
	}
	f, err := openMem(pid)
	if err != nil {
		return "", err
	}
	defer unix.Close(f)
	var out []byte
	buf := make([]byte, 256)
	for len(out) < unix.PathMax {
		// Never read across a page boundary in one go: the next page
		// may be unmapped even though the string ends before it.
		n := min(len(buf), int(4096-(addr%4096)))
		got, err := unix.Pread(f, buf[:n], int64(addr))
		if err != nil || got == 0 {
			return "", fmt.Errorf("read tracee memory: %v", err)
		}
		for i := 0; i < got; i++ {
			if buf[i] == 0 {
				return string(append(out, buf[:i]...)), nil
			}
		}
		out = append(out, buf[:got]...)
		addr += uint64(got)
	}
	return "", errors.New("string too long")
}

// readBytes reads n bytes of tracee memory (e.g. a struct sockaddr).
func readBytes(pid int, addr uint64, n int) ([]byte, error) {
	f, err := openMem(pid)
	if err != nil {
		return nil, err
	}
	defer unix.Close(f)
	b := make([]byte, n)
	got, err := unix.Pread(f, b, int64(addr))
	if err != nil {
		return nil, err
	}
	return b[:got], nil
}

func readUint64(pid int, addr uint64) (uint64, error) {
	b, err := readBytes(pid, addr, 8)
	if err != nil || len(b) < 8 {
		return 0, fmt.Errorf("short read: %v", err)
	}
	return binary.LittleEndian.Uint64(b), nil
}

func openMem(pid int) (int, error) {
	return unix.Open(fmt.Sprintf("/proc/%d/mem", pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
}

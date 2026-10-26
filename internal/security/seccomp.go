package security

import (
	"fmt"
	"sort"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// A seccomp filter is a small classic-BPF program that the kernel runs on
// every system call the process makes. It sees a struct seccomp_data:
//
//	offset 0   int   nr       syscall number
//	offset 4   u32   arch     AUDIT_ARCH_* of the calling convention
//	offset 8   u64   ip       instruction pointer
//	offset 16  u64   args[6]  syscall arguments
//
// and returns an action: allow, fail with an errno, kill, ... . Here we
// compile a list of Rules into such a program ourselves (rather than
// pulling in libseccomp via cgo), so every instruction is visible and
// testable.

// Action is what the filter does with a matching syscall.
type Action struct {
	Allow bool
	Errno unix.Errno // used when !Allow
}

var (
	ActAllow = Action{Allow: true}
	ActEPERM = Action{Errno: unix.EPERM}
)

func (a Action) ret() uint32 {
	if a.Allow {
		return unix.SECCOMP_RET_ALLOW
	}
	return unix.SECCOMP_RET_ERRNO | uint32(a.Errno)&unix.SECCOMP_RET_DATA
}

// CmpOp compares a 64-bit syscall argument with a value.
type CmpOp int

const (
	OpEQ       CmpOp = iota // arg == Value
	OpNE                    // arg != Value
	OpLT                    // arg <  Value (unsigned)
	OpMaskedEQ              // arg & Value == ValueTwo
)

// ArgCmp is one condition on argument Index (0-5).
type ArgCmp struct {
	Index    int
	Op       CmpOp
	Value    uint64
	ValueTwo uint64
}

// Rule applies Action to syscall Name when all Args conditions hold.
// Several rules for the same syscall are tried in order (logical OR).
type Rule struct {
	Name   string
	Action Action
	Args   []ArgCmp
}

// Filter is a complete seccomp policy.
type Filter struct {
	Default Action // for syscalls no rule matches
	Rules   []Rule
}

// Syscalls returns the sorted, de-duplicated names the filter mentions with
// an allowing rule. Used for reporting and for comparing profile sizes.
func (f *Filter) Syscalls() []string {
	seen := map[string]bool{}
	for _, r := range f.Rules {
		if r.Action.Allow {
			seen[r.Name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// seccomp_data field offsets (little-endian x86_64).
const (
	offNr   = 0
	offArch = 4
	offArgs = 16
)

// x32SyscallBit marks the x32 ABI (32-bit pointers on x86_64). We don't
// support it, and leaving it open would let a process reach the same
// kernel syscalls under different numbers, bypassing the filter.
const x32SyscallBit = 0x40000000

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// Compile turns the filter into a BPF program.
//
// Layout:
//
//	load arch; if arch != x86_64: kill process   (block i386/int 0x80 tricks)
//	load nr;   if nr >= x32 bit:  return default
//	for each syscall that has rules:
//	    if nr != N: skip this block
//	    for each rule: if all arg checks pass: return rule action
//	    return default
//	return default
//
// Every jump is forward and short (within one block), which keeps us under
// BPF's 8-bit jump offsets however many syscalls there are.
func (f *Filter) Compile() ([]unix.SockFilter, error) {
	prog := []unix.SockFilter{
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offArch),
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AUDIT_ARCH_X86_64, 1, 0),
		stmt(unix.BPF_RET|unix.BPF_K, unix.SECCOMP_RET_KILL_PROCESS),
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offNr),
		jump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, x32SyscallBit, 0, 1),
		stmt(unix.BPF_RET|unix.BPF_K, f.Default.ret()),
	}

	// Group rules by syscall number, keeping their order.
	byNr := map[int][]Rule{}
	var order []int
	for _, r := range f.Rules {
		nr, ok := syscallNumbers[r.Name]
		if !ok {
			return nil, fmt.Errorf("unknown syscall %q on x86_64", r.Name)
		}
		if _, seen := byNr[nr]; !seen {
			order = append(order, nr)
		}
		byNr[nr] = append(byNr[nr], r)
	}

	for _, nr := range order {
		block, err := compileSyscall(byNr[nr], f.Default)
		if err != nil {
			return nil, err
		}
		if len(block) > 255 {
			return nil, fmt.Errorf("too many rules for syscall %d", nr)
		}
		prog = append(prog, jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, uint32(nr), 0, uint8(len(block))))
		prog = append(prog, block...)
	}
	prog = append(prog, stmt(unix.BPF_RET|unix.BPF_K, f.Default.ret()))
	if len(prog) > unix.BPF_MAXINSNS {
		return nil, fmt.Errorf("filter has %d instructions, kernel limit is %d", len(prog), unix.BPF_MAXINSNS)
	}
	return prog, nil
}

// compileSyscall emits the rules for one syscall. Arg checks overwrite the
// accumulator (which held nr), but that is fine: once inside a syscall's
// block we never need nr again, because the block always ends in a return.
func compileSyscall(rules []Rule, def Action) ([]unix.SockFilter, error) {
	var block []unix.SockFilter
	for _, r := range rules {
		if len(r.Args) == 0 {
			// An unconditional rule always returns; later rules for the
			// same syscall can never be reached.
			return append(block, stmt(unix.BPF_RET|unix.BPF_K, r.Action.ret())), nil
		}
		// Each check jumps to "fail" (the end of this rule) on mismatch.
		var checks [][]unix.SockFilter
		for _, a := range r.Args {
			c, err := compileArg(a)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", r.Name, err)
			}
			checks = append(checks, c)
		}
		block = append(block, linkChecks(checks, r.Action)...)
	}
	return append(block, stmt(unix.BPF_RET|unix.BPF_K, def.ret())), nil
}

// failJump is a placeholder jump target meaning "this rule does not
// match". linkChecks rewrites it into a real offset.
const failJump = 0xff

// linkChecks concatenates arg checks followed by "return action", turning
// each failJump into an offset to the instruction after the return.
func linkChecks(checks [][]unix.SockFilter, act Action) []unix.SockFilter {
	var out []unix.SockFilter
	for _, c := range checks {
		out = append(out, c...)
	}
	out = append(out, stmt(unix.BPF_RET|unix.BPF_K, act.ret()))
	end := len(out) // index of the first instruction after this rule
	for i := range out {
		next := i + 1
		if out[i].Jt == failJump {
			out[i].Jt = uint8(end - next)
		}
		if out[i].Jf == failJump {
			out[i].Jf = uint8(end - next)
		}
	}
	return out
}

// compileArg emits a 64-bit comparison using 32-bit BPF loads: classic
// BPF can only load 32 bits at a time, so we check the high and low halves
// separately. On success it falls through; on failure it jumps to failJump.
func compileArg(a ArgCmp) ([]unix.SockFilter, error) {
	if a.Index < 0 || a.Index > 5 {
		return nil, fmt.Errorf("argument index %d out of range", a.Index)
	}
	lo := uint32(offArgs + 8*a.Index)
	hi := lo + 4
	vlo, vhi := uint32(a.Value), uint32(a.Value>>32)
	ld := func(off uint32) unix.SockFilter { return stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, off) }
	jeq := func(k uint32, jt, jf uint8) unix.SockFilter {
		return jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, k, jt, jf)
	}

	switch a.Op {
	case OpEQ:
		return []unix.SockFilter{
			ld(hi), jeq(vhi, 0, failJump),
			ld(lo), jeq(vlo, 0, failJump),
		}, nil
	case OpNE:
		// Matches unless both halves are equal.
		return []unix.SockFilter{
			ld(hi), jeq(vhi, 0, 2), // high differs: match, skip the low check
			ld(lo), jeq(vlo, failJump, 0),
		}, nil
	case OpLT:
		// hi < vhi, or hi == vhi and lo < vlo.
		return []unix.SockFilter{
			ld(hi),
			jump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, vhi, 0, 3), // hi < vhi: match
			jeq(vhi, 0, failJump), // hi > vhi: fail
			ld(lo),
			jump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, vlo, failJump, 0),
		}, nil
	case OpMaskedEQ:
		mlo, mhi := uint32(a.Value), uint32(a.Value>>32)
		wlo, whi := uint32(a.ValueTwo), uint32(a.ValueTwo>>32)
		and := func(m uint32) unix.SockFilter { return stmt(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, m) }
		return []unix.SockFilter{
			ld(hi), and(mhi), jeq(whi, 0, failJump),
			ld(lo), and(mlo), jeq(wlo, 0, failJump),
		}, nil
	}
	return nil, fmt.Errorf("unsupported comparison %d", a.Op)
}

// ExecLocked installs prog (if any) on the calling thread and then execs
// path, as two back-to-back raw system calls. On success it never returns.
//
// Why not install the filter first and call syscall.Exec afterwards? Once
// the filter is on, *any* syscall this thread makes must be in the
// allowlist, including the Go runtime's own. unix.Syscall returns through
// the scheduler (exitsyscall), which may call futex to wake another
// thread; syscall.Exec allocates first, and an allocation can start GC
// work that also uses futex. A policy for a program that never uses futex
// (a busybox shell, say) then makes the runtime crash before the command
// even starts. We saw this in about 1 run in 20. RawSyscall skips the
// scheduler hooks, and every pointer execve needs is built beforehand, so
// no Go code runs between the two calls.
//
// The caller must have set no_new_privs (seccomp requires it unless we
// hold CAP_SYS_ADMIN, so that a filter can't confuse a setuid program) and
// locked its goroutine to this OS thread.
//
// We deliberately do not pass SECCOMP_FILTER_FLAG_TSYNC. The filter only
// needs to be on the thread that execs: exec discards all other threads,
// and the new program inherits this thread's filter.
func ExecLocked(prog []unix.SockFilter, path string, argv, env []string) error {
	pathp, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	envp, err := syscall.SlicePtrFromStrings(env)
	if err != nil {
		return err
	}
	if len(prog) > 0 {
		fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
		_, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&fprog)))
		if errno != 0 {
			return fmt.Errorf("seccomp(SET_MODE_FILTER): %w", errno)
		}
	}
	_, _, errno := unix.RawSyscall(unix.SYS_EXECVE, uintptr(unsafe.Pointer(pathp)),
		uintptr(unsafe.Pointer(&argvp[0])), uintptr(unsafe.Pointer(&envp[0])))
	// Only reached if execve failed. The filter is on now, so even
	// reporting the error may be denied; init then exits with 127.
	return fmt.Errorf("execve %s: %w", path, errno)
}

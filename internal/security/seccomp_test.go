package security

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// runBPF is a minimal classic-BPF interpreter covering the instructions
// Compile emits. It lets us test filters without installing them (which
// would restrict the test process itself).
func runBPF(t *testing.T, prog []unix.SockFilter, data []byte) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			acc = binary.LittleEndian.Uint32(data[in.K:])
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			acc &= in.K
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			var cond bool
			if in.Code&0xf0 == unix.BPF_JEQ {
				cond = acc == in.K
			} else {
				cond = acc >= in.K
			}
			if cond {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		default:
			t.Fatalf("unexpected instruction %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("program ran off the end without returning")
	return 0
}

// call builds a struct seccomp_data for an x86_64 syscall.
func call(name string, args ...uint64) []byte {
	return callArch(unix.AUDIT_ARCH_X86_64, uint32(syscallNumbers[name]), args...)
}

func callArch(arch, nr uint32, args ...uint64) []byte {
	d := make([]byte, 64)
	binary.LittleEndian.PutUint32(d[0:], nr)
	binary.LittleEndian.PutUint32(d[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(d[16+8*i:], a)
	}
	return d
}

const (
	retAllow = unix.SECCOMP_RET_ALLOW
	retEPERM = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
)

func compile(t *testing.T, f *Filter) []unix.SockFilter {
	t.Helper()
	prog, err := f.Compile()
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

func TestDockerBaseline(t *testing.T) {
	f, err := DockerFilter(DefaultCaps)
	if err != nil {
		t.Fatal(err)
	}
	prog := compile(t, f)

	cases := []struct {
		name string
		data []byte
		want uint32
	}{
		{"read allowed", call("read", 0, 0, 0), retAllow},
		{"execve allowed", call("execve"), retAllow},
		{"mount needs CAP_SYS_ADMIN", call("mount"), retEPERM},
		{"unshare needs CAP_SYS_ADMIN", call("unshare", unix.CLONE_NEWUSER), retEPERM},
		{"init_module blocked", call("init_module"), retEPERM},
		{"keyctl blocked", call("keyctl"), retEPERM},
		{"bpf blocked", call("bpf"), retEPERM},
		{"chroot allowed with CAP_SYS_CHROOT", call("chroot"), retAllow},
		{"clone for a thread allowed", call("clone", unix.CLONE_VM|unix.CLONE_THREAD|unix.CLONE_SIGHAND), retAllow},
		{"clone with CLONE_NEWUSER blocked", call("clone", unix.CLONE_NEWUSER), retEPERM},
		{"clone3 gets ENOSYS (libc falls back to clone)", call("clone3"), unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
		{"personality(PER_LINUX) allowed", call("personality", 0), retAllow},
		{"personality query allowed", call("personality", 0xffffffff), retAllow},
		{"personality(READ_IMPLIES_EXEC) blocked", call("personality", 0x0400000), retEPERM},
		{"socket(AF_INET) allowed", call("socket", unix.AF_INET), retAllow},
		{"socket(AF_VSOCK) blocked", call("socket", unix.AF_VSOCK), retEPERM},
		{"socket with high bits set blocked", call("socket", 1<<32|unix.AF_INET), retEPERM},
		{"32-bit (i386) ABI killed", callArch(unix.AUDIT_ARCH_I386, 1), unix.SECCOMP_RET_KILL_PROCESS},
		{"x32 ABI denied", callArch(unix.AUDIT_ARCH_X86_64, x32SyscallBit|0), retEPERM},
	}
	for _, c := range cases {
		if got := runBPF(t, prog, c.data); got != c.want {
			t.Errorf("%s: got %#x, want %#x", c.name, got, c.want)
		}
	}
}

func TestDockerWithSysAdmin(t *testing.T) {
	f, err := DockerFilter(append([]string{"CAP_SYS_ADMIN"}, DefaultCaps...))
	if err != nil {
		t.Fatal(err)
	}
	prog := compile(t, f)
	if got := runBPF(t, prog, call("mount")); got != retAllow {
		t.Errorf("mount with CAP_SYS_ADMIN: got %#x", got)
	}
	if got := runBPF(t, prog, call("clone", unix.CLONE_NEWUSER)); got != retAllow {
		t.Errorf("clone(NEWUSER) with CAP_SYS_ADMIN: got %#x", got)
	}
}

func TestDockerProfileSize(t *testing.T) {
	f, err := DockerFilter(DefaultCaps)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity bounds, not an exact number: the exact count is reported by
	// the Phase 6 scripts. Docker allows a bit over 300 syscalls on x86_64.
	if n := len(f.Syscalls()); n < 250 || n > 385 {
		t.Errorf("Docker baseline allows %d syscalls, outside the plausible range", n)
	}
}

func TestArgOps(t *testing.T) {
	f := &Filter{Default: ActEPERM, Rules: []Rule{
		{Name: "read", Action: ActAllow, Args: []ArgCmp{{Index: 2, Op: OpLT, Value: 1<<32 | 10}}},
		{Name: "write", Action: ActAllow, Args: []ArgCmp{{Index: 0, Op: OpNE, Value: 1<<32 | 5}}},
		{Name: "close", Action: ActAllow, Args: []ArgCmp{
			{Index: 0, Op: OpMaskedEQ, Value: 0xff00, ValueTwo: 0x1200},
			{Index: 1, Op: OpEQ, Value: 7},
		}},
	}}
	prog := compile(t, f)
	cases := []struct {
		data []byte
		want uint32
	}{
		{call("read", 0, 0, 5), retAllow},        // hi 0 < 1
		{call("read", 0, 0, 1<<32|9), retAllow},  // same hi, lo 9 < 10
		{call("read", 0, 0, 1<<32|10), retEPERM}, // equal: not less
		{call("read", 0, 0, 2<<32), retEPERM},    // hi greater
		{call("write", 5), retAllow},             // differs in hi
		{call("write", 1<<32|6), retAllow},       // differs in lo
		{call("write", 1<<32|5), retEPERM},       // equal
		{call("close", 0x12ab, 7), retAllow},     // mask matches, arg1 == 7
		{call("close", 0x13ab, 7), retEPERM},     // mask mismatch
		{call("close", 0x12ab, 8), retEPERM},     // second condition fails (AND)
		{call("openat"), retEPERM},               // no rule: default
	}
	for i, c := range cases {
		if got := runBPF(t, prog, c.data); got != c.want {
			t.Errorf("case %d: got %#x, want %#x", i, got, c.want)
		}
	}
}

func TestPolicyFilter(t *testing.T) {
	c := Config{Mode: Policy, Syscalls: []string{"read", "write", "exit_group"}}
	f, err := c.SeccompFilter()
	if err != nil {
		t.Fatal(err)
	}
	prog := compile(t, f)
	for name, want := range map[string]uint32{
		"read": retAllow, "write": retAllow, "exit_group": retAllow,
		"execve": retAllow, // always allowed so the command can start
		"openat": retEPERM, "mount": retEPERM, "ptrace": retEPERM,
	} {
		if got := runBPF(t, prog, call(name)); got != want {
			t.Errorf("%s: got %#x, want %#x", name, got, want)
		}
	}
}

func TestPolicyRestrictsClone(t *testing.T) {
	c := Config{Mode: Policy, Syscalls: []string{"clone3", "read"}}
	f, _ := c.SeccompFilter()
	prog := compile(t, f)
	cases := map[string]struct {
		data []byte
		want uint32
	}{
		"thread clone allowed (clone3 seen, so clone is added)": {call("clone", unix.CLONE_VM|unix.CLONE_THREAD), retAllow},
		"clone(CLONE_NEWUSER) denied":                           {call("clone", unix.CLONE_NEWUSER), retEPERM},
		"clone3 -> ENOSYS so libc falls back":                   {call("clone3"), unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
	}
	for name, tc := range cases {
		if got := runBPF(t, prog, tc.data); got != tc.want {
			t.Errorf("%s: got %#x, want %#x", name, got, tc.want)
		}
	}

	// An app that really creates namespaces was given CAP_SYS_ADMIN by
	// the profiler, and keeps unrestricted clone.
	c = Config{Mode: Policy, Syscalls: []string{"clone", "read"}, Caps: []string{"CAP_SYS_ADMIN"}}
	f, _ = c.SeccompFilter()
	if got := runBPF(t, compile(t, f), call("clone", unix.CLONE_NEWUSER)); got != retAllow {
		t.Errorf("with CAP_SYS_ADMIN: clone(CLONE_NEWUSER) = %#x, want allow", got)
	}
	// No clone at all in the policy: none is added.
	c = Config{Mode: Policy, Syscalls: []string{"read"}}
	f, _ = c.SeccompFilter()
	if got := runBPF(t, compile(t, f), call("clone", 0)); got != retEPERM {
		t.Errorf("clone not profiled: got %#x, want EPERM", got)
	}
}

func TestUnknownSyscallRejected(t *testing.T) {
	f := &Filter{Default: ActEPERM, Rules: []Rule{{Name: "no_such_syscall", Action: ActAllow}}}
	if _, err := f.Compile(); err == nil {
		t.Error("expected an error for an unknown syscall")
	}
}

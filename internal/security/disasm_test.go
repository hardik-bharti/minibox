package security

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEvaluateMatchesInterpreter cross-checks Evaluate against the test
// interpreter (runBPF) on the Docker baseline and a small policy.
func TestEvaluateMatchesInterpreter(t *testing.T) {
	docker, err := DockerFilter(DefaultCaps)
	if err != nil {
		t.Fatal(err)
	}
	filters := map[string]*Filter{
		"docker": docker,
		"policy": policyFilter([]string{"read", "write", "clone"}, nil),
	}
	calls := []struct {
		name string
		args []uint64
	}{
		{"read", nil}, {"mount", nil}, {"getpid", nil}, {"ptrace", nil},
		{"clone", []uint64{uint64(unix.SIGCHLD)}},
		{"clone", []uint64{unix.CLONE_NEWUSER}},
		{"clone3", nil},
	}
	for fname, f := range filters {
		prog := compile(t, f)
		for _, c := range calls {
			var args [6]uint64
			copy(args[:], c.args)
			got, path, err := Evaluate(prog, syscallNumbers[c.name], args)
			if err != nil {
				t.Fatalf("%s/%s: %v", fname, c.name, err)
			}
			if want := runBPF(t, prog, call(c.name, c.args...)); got != want {
				t.Errorf("%s/%s: Evaluate = %s, interpreter = %s", fname, c.name, RetName(got), RetName(want))
			}
			if last := prog[path[len(path)-1]]; last.Code != unix.BPF_RET|unix.BPF_K {
				t.Errorf("%s/%s: path does not end at a return", fname, c.name)
			}
		}
	}
}

func TestDisassemble(t *testing.T) {
	prog := compile(t, policyFilter([]string{"getpid"}, nil))
	insns := Disassemble(prog)
	if len(insns) != len(prog) {
		t.Fatalf("got %d instructions, want %d", len(insns), len(prog))
	}
	text := ""
	for _, i := range insns {
		text += i.Asm + " | " + i.Explain + "\n"
	}
	for _, want := range []string{
		"load arch",
		"if arch == 0xc000003e (x86_64)",
		"return KILL_PROCESS",
		"if syscall number == 39 (getpid)",
		"return ALLOW",
		"return ERRNO(EPERM)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("disassembly lacks %q:\n%s", want, text)
		}
	}
}

func TestRetName(t *testing.T) {
	cases := map[uint32]string{
		unix.SECCOMP_RET_ALLOW:                       "ALLOW",
		unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS): "ERRNO(ENOSYS)",
		unix.SECCOMP_RET_KILL_PROCESS:                "KILL_PROCESS",
		unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM):  "ERRNO(EPERM)",
	}
	for k, want := range cases {
		if got := RetName(k); got != want {
			t.Errorf("RetName(%#x) = %q, want %q", k, got, want)
		}
	}
}

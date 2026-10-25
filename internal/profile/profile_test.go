package profile

import (
	"reflect"
	"testing"

	"github.com/hardik-bharti/minibox/internal/security"
)

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

func TestWritablePaths(t *testing.T) {
	cases := []struct {
		name             string
		written, created map[string]bool
		want             []string
	}{
		{"nothing", set(), set(), []string{}},
		{"file inside a writable dir is covered",
			set("/tmp/a.txt", "/var/log/app.log"), set("/tmp"),
			[]string{"/tmp", "/var/log/app.log"}},
		{"nested dirs collapse to the outermost",
			set(), set("/var/cache", "/var/cache/app", "/var/cache/app/x"),
			[]string{"/var/cache"}},
		{"separate mounts and / are dropped",
			set("/dev/null", "/proc/self/oom_score_adj", "/sys/x"), set("/", "/data"),
			[]string{"/data"}},
		{"similar prefix is not a parent",
			set("/tmpfile"), set("/tmp"),
			[]string{"/tmp", "/tmpfile"}},
	}
	for _, c := range cases {
		if got := writablePaths(c.written, c.created); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMerge(t *testing.T) {
	a := &security.PolicyFile{
		Syscalls: []string{"read", "write"}, Capabilities: []string{"CAP_CHOWN"},
		WritablePaths: []string{"/tmp/x", "/var/log"},
		Observed:      security.Observed{SyscallCounts: map[string]int{"read": 2}},
	}
	b := &security.PolicyFile{
		Syscalls: []string{"openat", "read"}, Capabilities: nil,
		WritablePaths: []string{"/tmp"},
		Observed:      security.Observed{SyscallCounts: map[string]int{"read": 3}},
	}
	m := Merge(a, b)
	if want := []string{"openat", "read", "write"}; !reflect.DeepEqual(m.Syscalls, want) {
		t.Errorf("syscalls = %v, want %v", m.Syscalls, want)
	}
	if want := []string{"CAP_CHOWN"}; !reflect.DeepEqual(m.Capabilities, want) {
		t.Errorf("caps = %v, want %v", m.Capabilities, want)
	}
	if want := []string{"/tmp", "/var/log"}; !reflect.DeepEqual(m.WritablePaths, want) {
		t.Errorf("writable = %v, want %v", m.WritablePaths, want)
	}
	if m.Observed.SyscallCounts["read"] != 5 {
		t.Errorf("counts not summed: %v", m.Observed.SyscallCounts)
	}
}

func TestPathSyscallsExist(t *testing.T) {
	// A typo here would silently stop path recording for that syscall.
	for name := range pathSyscalls {
		found := false
		for nr := 0; nr < 1024 && !found; nr++ {
			n, ok := security.SyscallName(nr)
			found = ok && n == name
		}
		if !found {
			t.Errorf("pathSyscalls has unknown syscall %q", name)
		}
	}
}

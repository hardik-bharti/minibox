package security

import (
	"path/filepath"
	"testing"
)

func TestDefaultCapsMask(t *testing.T) {
	// 0xa80425fb is the CapEff value `docker run` shows in
	// /proc/self/status, so our default set matches Docker's exactly.
	var mask uint64
	for _, c := range DefaultCaps {
		n, err := CapNumber(c)
		if err != nil {
			t.Fatal(err)
		}
		mask |= 1 << n
	}
	if mask != 0xa80425fb {
		t.Errorf("default caps mask = %#x, want 0xa80425fb", mask)
	}
}

func TestCapNumber(t *testing.T) {
	if n, err := CapNumber("cap_sys_admin"); err != nil || n != 21 {
		t.Errorf("CapNumber(cap_sys_admin) = %d, %v", n, err)
	}
	if _, err := CapNumber("CAP_WIZARD"); err == nil {
		t.Error("CAP_WIZARD accepted")
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"": Baseline, "baseline": Baseline, "none": None} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseMode("policy"); err == nil {
		t.Error("policy must be selected with --policy, not --security")
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	p := &PolicyFile{
		Version:       PolicyVersion,
		Command:       []string{"sh"},
		Syscalls:      []string{"read", "write"},
		Capabilities:  []string{"CAP_CHOWN"},
		WritablePaths: []string{"/tmp"},
	}
	path := filepath.Join(t.TempDir(), "p.json")
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Syscalls) != 2 || got.WritablePaths[0] != "/tmp" {
		t.Errorf("round trip lost data: %+v", got)
	}
}

func TestPolicyValidate(t *testing.T) {
	base := func() PolicyFile {
		return PolicyFile{Version: 1, Syscalls: []string{"read"}, Capabilities: nil, WritablePaths: []string{"/tmp"}}
	}
	bad := map[string]func(*PolicyFile){
		"wrong version":   func(p *PolicyFile) { p.Version = 99 },
		"no syscalls":     func(p *PolicyFile) { p.Syscalls = nil },
		"unknown syscall": func(p *PolicyFile) { p.Syscalls = []string{"frobnicate"} },
		"unknown cap":     func(p *PolicyFile) { p.Capabilities = []string{"CAP_NOPE"} },
		"relative path":   func(p *PolicyFile) { p.WritablePaths = []string{"tmp"} },
		"unclean path":    func(p *PolicyFile) { p.WritablePaths = []string{"/tmp/../etc"} },
	}
	for name, mutate := range bad {
		p := base()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := base()
	if err := p.Validate(); err != nil {
		t.Errorf("valid policy rejected: %v", err)
	}
}

package cgroups

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMemory(t *testing.T) {
	good := map[string]int64{
		"4096": 4096,
		"512k": 512 << 10,
		"64m":  64 << 20,
		"64M":  64 << 20,
		"64mb": 64 << 20,
		"1g":   1 << 30,
		" 2G ": 2 << 30,
	}
	for in, want := range good {
		got, err := ParseMemory(in)
		if err != nil || got != want {
			t.Errorf("ParseMemory(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "m", "abc", "-5m", "0", "1.5g", "10t"} {
		if _, err := ParseMemory(in); err == nil {
			t.Errorf("ParseMemory(%q) should fail", in)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := []Limits{
		{},
		{MemoryBytes: 64 << 20, CPUs: 0.5, Pids: 100},
		{Pids: MinPids},
		{CPUs: 0.01},
	}
	for _, l := range ok {
		if err := l.Validate(); err != nil {
			t.Errorf("%+v: unexpected error %v", l, err)
		}
	}
	bad := []Limits{
		{MemoryBytes: -1},
		{Pids: MinPids - 1},
		{CPUs: 0.001},  // below the kernel's 1ms minimum quota
		{CPUs: 100000}, // more CPUs than any test machine has
	}
	for _, l := range bad {
		if err := l.Validate(); err == nil {
			t.Errorf("%+v: expected an error", l)
		}
	}
}

func TestIsZero(t *testing.T) {
	if !(Limits{}).IsZero() {
		t.Error("empty Limits should be zero")
	}
	if (Limits{Pids: 10}).IsZero() {
		t.Error("Limits with Pids set should not be zero")
	}
}

func TestCPUQuota(t *testing.T) {
	// 0.5 CPUs = 50ms of CPU time per 100ms period.
	if got := cpuQuota(0.5); got != 50_000 {
		t.Errorf("cpuQuota(0.5) = %d, want 50000", got)
	}
	if got := cpuQuota(2); got != 200_000 {
		t.Errorf("cpuQuota(2) = %d, want 200000", got)
	}
}

func TestStatsParsing(t *testing.T) {
	// A fake cgroup dir with the accounting files the kernel provides.
	dir := t.TempDir()
	files := map[string]string{
		"cpu.stat":      "usage_usec 1500\nuser_usec 1000\nnr_periods 10\nnr_throttled 4\nthrottled_usec 900\n",
		"memory.events": "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n",
		"pids.events":   "max 7\n",
		"memory.peak":   "52428800\n",
		"pids.peak":     "20\n",
	}
	for name, content := range files {
		os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600)
	}

	got := (&Cgroup{Path: dir}).Stats()
	want := Stats{CPUUsageUsec: 1500, NrThrottled: 4, ThrottledUsec: 900,
		MemoryPeak: 52428800, OOMKills: 1, PidsPeak: 20, PidsRejected: 7}
	if got != want {
		t.Errorf("Stats() = %+v\nwant      %+v", got, want)
	}
}

package cgroups

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// Limits are the resource limits a container can be given. A zero field
// means "no limit".
type Limits struct {
	MemoryBytes int64   // memory.max (and memory.swap.max = 0)
	CPUs        float64 // cpu.max quota, in CPUs (0.5 = half of one CPU)
	Pids        int64   // pids.max: maximum number of processes/threads
}

// IsZero reports whether no limit is set, in which case minibox skips
// cgroup setup entirely.
func (l Limits) IsZero() bool {
	return l.MemoryBytes == 0 && l.CPUs == 0 && l.Pids == 0
}

// Validate rejects limits the kernel would accept but that make no sense.
func (l Limits) Validate() error {
	if l.MemoryBytes < 0 || l.CPUs < 0 || l.Pids < 0 {
		return fmt.Errorf("limits must not be negative")
	}
	if l.Pids != 0 && l.Pids < MinPids {
		return fmt.Errorf("--pids %d is too low: minimum is %d, because pids.max counts threads "+
			"and minibox's own setup process (Go) needs a few before it execs your command", l.Pids, MinPids)
	}
	if n := float64(runtime.NumCPU()); l.CPUs > n {
		return fmt.Errorf("--cpus %.2f is more than the %d CPUs on this machine", l.CPUs, int(n))
	}
	if l.CPUs != 0 && cpuQuota(l.CPUs) < minQuotaUsec {
		return fmt.Errorf("--cpus %.4f is below the kernel minimum of 0.01", l.CPUs)
	}
	return nil
}

// MinPids is the smallest --pids we accept. The container's first process is
// minibox init, a Go program, and the Go runtime starts several threads,
// each counted by pids.max. On this 4-CPU VM we measured a peak of 5 tasks
// by default and 3-4 with GOMAXPROCS=1 (which container.startInit sets), so
// 8 leaves a safety margin.
const MinPids = 8

// cpuPeriodUsec is the CFS bandwidth period: every 100ms the group may run
// for at most quota microseconds of CPU time (summed over all CPUs). 100ms
// is the kernel's (and Docker's) default.
const cpuPeriodUsec = 100_000

// minQuotaUsec is the smallest quota the kernel accepts (1ms).
const minQuotaUsec = 1000

func cpuQuota(cpus float64) int64 {
	return int64(cpus * cpuPeriodUsec)
}

// ParseMemory parses sizes like "512k", "64m", "1g" or a plain byte count.
// Suffixes are powers of 1024, as in Docker.
func ParseMemory(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, "b") // allow "64mb" as well as "64m"
	mult := int64(1)
	if n := len(s); n > 0 {
		switch s[n-1] {
		case 'k':
			mult = 1 << 10
		case 'm':
			mult = 1 << 20
		case 'g':
			mult = 1 << 30
		}
		if mult != 1 {
			s = s[:n-1]
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("invalid memory size %q (examples: 64m, 1g)", s)
	}
	return v * mult, nil
}

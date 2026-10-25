package cgroups

import (
	"fmt"
	"path/filepath"
)

// Stats is a snapshot of what the container used, read from the cgroup's
// accounting files just before the cgroup is removed.
type Stats struct {
	CPUUsageUsec  int64 // cpu.stat usage_usec: total CPU time used
	NrThrottled   int64 // cpu.stat nr_throttled: periods in which the quota ran out
	ThrottledUsec int64 // cpu.stat throttled_usec: time spent waiting for the next period
	MemoryPeak    int64 // memory.peak: highest memory use, in bytes
	OOMKills      int64 // memory.events oom_kill: processes killed for exceeding memory.max
	PidsPeak      int64 // pids.peak: most processes alive at once
	PidsRejected  int64 // pids.events max: fork/clone calls refused by pids.max
}

// Stats reads the accounting files. Missing files (e.g. on older kernels)
// leave the corresponding field at zero.
func (c *Cgroup) Stats() Stats {
	var s Stats
	if m, err := readKeyValues(filepath.Join(c.Path, "cpu.stat")); err == nil {
		s.CPUUsageUsec = m["usage_usec"]
		s.NrThrottled = m["nr_throttled"]
		s.ThrottledUsec = m["throttled_usec"]
	}
	if m, err := readKeyValues(filepath.Join(c.Path, "memory.events")); err == nil {
		s.OOMKills = m["oom_kill"]
	}
	if m, err := readKeyValues(filepath.Join(c.Path, "pids.events")); err == nil {
		s.PidsRejected = m["max"]
	}
	s.MemoryPeak, _ = readInt(filepath.Join(c.Path, "memory.peak"))
	s.PidsPeak, _ = readInt(filepath.Join(c.Path, "pids.peak"))
	return s
}

// String formats Stats as key=value pairs, easy to read and to grep in tests.
func (s Stats) String() string {
	return fmt.Sprintf("cpu_usage_usec=%d nr_throttled=%d throttled_usec=%d memory_peak_bytes=%d oom_kills=%d pids_peak=%d pids_rejected=%d",
		s.CPUUsageUsec, s.NrThrottled, s.ThrottledUsec, s.MemoryPeak, s.OOMKills, s.PidsPeak, s.PidsRejected)
}

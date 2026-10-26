package ui

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Meter is one reading of a container's cgroup, taken straight from the
// kernel's accounting files. Limits of 0 mean "max" (no limit).
type Meter struct {
	TMs          int64   `json:"t_ms"`          // since the watch started
	MemBytes     int64   `json:"mem"`           // memory.current
	MemMax       int64   `json:"mem_max"`       // memory.max
	Pids         int64   `json:"pids"`          // pids.current
	PidsMax      int64   `json:"pids_max"`      // pids.max
	CPUUsec      int64   `json:"cpu_usec"`      // cpu.stat usage_usec (cumulative)
	CPUCores     float64 `json:"cpu_cores"`     // CPUs used over the last cpuWindow
	CPULimit     float64 `json:"cpu_limit"`     // cpu.max quota/period, in CPUs
	Throttled    int64   `json:"throttled"`     // cpu.stat nr_throttled
	OOMKills     int64   `json:"oom_kills"`     // memory.events oom_kill
	PidsRejected int64   `json:"pids_rejected"` // pids.events max
}

const (
	cgroupRoot   = "/sys/fs/cgroup"
	meterEvery   = 100 * time.Millisecond
	findCgroupIn = 5 * time.Second
	// cpuWindow is the span the CPU rate is averaged over. cpu.max grants
	// quota per 100 ms period, the same length as meterEvery, so a rate
	// over a single reading aliases with the periods: a window that is a
	// little short or long catches one burst more or less and shows a
	// spike (we saw 1.2 CPUs under --cpus 0.25). Five periods smooth that.
	cpuWindow = 500 * time.Millisecond
)

// containerCgroup finds the cgroup minibox created for its container.
//
// minibox (cgroups.Create) moves itself into <scope>/supervisor and puts the
// container in <scope>/<container-id>. So from minibox's PID we read
// /proc/<pid>/cgroup, and once it ends in /supervisor, the container's
// cgroup is the only other directory next to it. We don't need minibox to
// tell us anything: the kernel's own bookkeeping is enough.
func containerCgroup(pid int) (string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", err
	}
	rel, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "0::")
	if !ok || filepath.Base(rel) != "supervisor" {
		return "", errNotYet
	}
	scope := filepath.Join(cgroupRoot, filepath.Dir(rel))
	entries, err := os.ReadDir(scope)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != "supervisor" {
			return filepath.Join(scope, e.Name()), nil
		}
	}
	return "", errNotYet
}

var errNotYet = errors.New("container cgroup not created yet")

// watchCgroup sends a Meter every meterEvery until ctx ends or the cgroup
// is removed (minibox removes it when the container exits). The last
// reading is the one taken just before removal.
func watchCgroup(ctx context.Context, pid int, send func(Meter)) {
	var dir string
	deadline := time.Now().Add(findCgroupIn)
	for dir == "" {
		d, err := containerCgroup(pid)
		if err == nil {
			dir = d
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	start := time.Now()
	var recent []Meter // readings in the last cpuWindow, oldest first
	tick := time.NewTicker(meterEvery)
	defer tick.Stop()
	for {
		// Timestamp before reading, so the time matches the CPU counter.
		t := time.Since(start).Milliseconds()
		m, err := readMeter(dir)
		if err != nil {
			return // cgroup removed: the container has exited
		}
		m.TMs = t
		m.CPUCores = cpuRate(recent, m)
		send(m)
		recent = append(recent, m)
		for len(recent) > 1 && m.TMs-recent[1].TMs >= cpuWindow.Milliseconds() {
			recent = recent[1:]
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// cpuRate is CPU use as a rate: CPU time used divided by wall time passed,
// measured from the oldest reading in recent to m.
func cpuRate(recent []Meter, m Meter) float64 {
	if len(recent) == 0 {
		return 0
	}
	old := recent[0]
	dt := m.TMs - old.TMs
	if dt <= 0 {
		return 0
	}
	return float64(m.CPUUsec-old.CPUUsec) / float64(dt*1000)
}

// readMeter reads one Meter from cgroup directory dir.
func readMeter(dir string) (Meter, error) {
	var m Meter
	var err error
	// memory.current is read first and is the only required file: if it
	// is gone, so is the cgroup.
	if m.MemBytes, err = readNumber(filepath.Join(dir, "memory.current")); err != nil {
		return m, err
	}
	m.MemMax, _ = readNumber(filepath.Join(dir, "memory.max"))
	m.Pids, _ = readNumber(filepath.Join(dir, "pids.current"))
	m.PidsMax, _ = readNumber(filepath.Join(dir, "pids.max"))
	cpu := readKV(filepath.Join(dir, "cpu.stat"))
	m.CPUUsec, m.Throttled = cpu["usage_usec"], cpu["nr_throttled"]
	m.OOMKills = readKV(filepath.Join(dir, "memory.events"))["oom_kill"]
	m.PidsRejected = readKV(filepath.Join(dir, "pids.events"))["max"]
	m.CPULimit = readCPUMax(filepath.Join(dir, "cpu.max"))
	return m, nil
}

// readNumber reads a single-value cgroup file. "max" (no limit) is 0.
func readNumber(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "max" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// readKV parses "key value" lines (cpu.stat, memory.events, pids.events).
func readKV(path string) map[string]int64 {
	m := map[string]int64{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), " ")
		if !ok {
			continue
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			m[k] = n
		}
	}
	return m
}

// readCPUMax turns cpu.max ("50000 100000" or "max 100000") into CPUs.
func readCPUMax(path string) float64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	quota, period, ok := strings.Cut(strings.TrimSpace(string(b)), " ")
	q, err1 := strconv.ParseFloat(quota, 64)
	p, err2 := strconv.ParseFloat(period, 64)
	if !ok || err1 != nil || err2 != nil || p == 0 {
		return 0 // "max": unlimited
	}
	return q / p
}

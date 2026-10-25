package profile

import (
	"fmt"
	"path"
	"sort"
	"syscall"
	"time"

	"github.com/hardik-bharti/minibox/internal/container"
	"github.com/hardik-bharti/minibox/internal/security"
)

// Profiler traces a container and builds a policy from what it saw. It
// implements container.Tracer.
type Profiler struct {
	rec *recorder
}

func (p *Profiler) Trace(pid int) (syscall.WaitStatus, error) {
	t := &tracer{h: p.rec}
	return t.trace(pid)
}

// Run profiles the container described by c and returns its result and
// the generated policy.
//
// The container runs with --security none: no seccomp and every
// capability, so we observe everything the program tries to do rather
// than what a previous policy let it do.
func Run(c *container.Config) (container.Result, *security.PolicyFile, error) {
	p := &Profiler{rec: newRecorder()}
	c.Tracer = p
	c.Security = security.Config{Mode: security.None}
	res, err := container.Run(c)
	if err != nil {
		return res, nil, err
	}
	pol := p.rec.policy(c.Command)
	for nr, n := range p.rec.unknown {
		// Newer than our syscall table: can't name it, so can't allow it.
		pol.Warnings = append(pol.Warnings,
			fmt.Sprintf("syscall %d (called %d times) is not in the x86_64 table; regenerate it with scripts/gen-syscalls.sh", nr, n))
	}
	if len(pol.Syscalls) == 0 {
		pol.Warnings = append(pol.Warnings, "no syscalls recorded: did the command start?")
	}
	return res, pol, nil
}

// policy turns the observations into a policy file.
func (r *recorder) policy(cmd []string) *security.PolicyFile {
	return &security.PolicyFile{
		Version:       security.PolicyVersion,
		Generated:     time.Now().UTC().Truncate(time.Second),
		Command:       cmd,
		Syscalls:      sortedKeys(r.counts),
		Capabilities:  sortedKeys(r.caps),
		WritablePaths: writablePaths(r.written, r.created),
		Observed: security.Observed{
			SyscallCounts: r.counts,
			CapReasons:    r.caps,
			ReadPaths:     sortedKeys(r.read),
			WrittenPaths:  sortedKeys(union(r.written, r.created)),
		},
	}
}

// writablePaths merges in-place writes and directory changes, drops paths
// on separate mounts (/dev, /proc, /sys), and removes any path inside
// another writable directory, so the policy lists the fewest, broadest
// mounts needed. Example: {/tmp, /tmp/a.txt, /var/log/app.log} ->
// {/tmp, /var/log/app.log}.
func writablePaths(written, created map[string]bool) []string {
	all := map[string]bool{}
	for p := range union(written, created) {
		if !underAny(p, ignoredWritePrefixes) && p != "/" {
			all[p] = true
		}
	}
	// "/" itself as a writable dir would defeat the whole read-only
	// root; it only appears if the app creates files at the top level,
	// which then simply fails under the policy. Reported via Observed.
	out := []string{} // [] rather than null in the JSON
	for p := range all {
		covered := false
		for d := path.Dir(p); d != "/" && d != "."; d = path.Dir(d) {
			if all[d] { // a writable bind of d covers everything below it
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// Merge combines two policies for the same program, e.g. from profiling
// it under different workloads: the union of syscalls, capabilities and
// writable paths. Tracing only sees code paths that actually ran, so
// merging several runs is how to improve coverage.
func Merge(a, b *security.PolicyFile) *security.PolicyFile {
	set := func(lists ...[]string) map[string]bool {
		m := map[string]bool{}
		for _, l := range lists {
			for _, s := range l {
				m[s] = true
			}
		}
		return m
	}
	counts := map[string]int{}
	for _, p := range []*security.PolicyFile{a, b} {
		for k, v := range p.Observed.SyscallCounts {
			counts[k] += v
		}
	}
	reasons := map[string]string{}
	for _, p := range []*security.PolicyFile{a, b} {
		for k, v := range p.Observed.CapReasons {
			reasons[k] = v
		}
	}
	out := *b // newest metadata (command, time)
	out.Syscalls = sortedKeys(set(a.Syscalls, b.Syscalls))
	out.Capabilities = sortedKeys(set(a.Capabilities, b.Capabilities))
	out.WritablePaths = writablePaths(set(a.WritablePaths, b.WritablePaths), nil)
	out.Observed = security.Observed{
		SyscallCounts: counts,
		CapReasons:    reasons,
		ReadPaths:     sortedKeys(set(a.Observed.ReadPaths, b.Observed.ReadPaths)),
		WrittenPaths:  sortedKeys(set(a.Observed.WrittenPaths, b.Observed.WrittenPaths)),
	}
	return &out
}

func union(a, b map[string]bool) map[string]bool {
	m := make(map[string]bool, len(a)+len(b))
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

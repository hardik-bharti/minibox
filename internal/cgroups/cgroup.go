package cgroups

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Root is where the cgroup v2 unified hierarchy is mounted.
const Root = "/sys/fs/cgroup"

// controllers are the ones we use. Each must be delegated to our user by
// systemd (check-env.sh verifies this).
var controllers = []string{"cpu", "memory", "pids"}

// Cgroup is one container's cgroup directory.
type Cgroup struct {
	Path string
}

// ErrNotDelegated means our current cgroup is not owned by us, so we cannot
// create child cgroups in it. The fix is to run inside a delegated systemd
// scope (see cmd/minibox: reexecInScope).
var ErrNotDelegated = errors.New("current cgroup is not delegated to this user")

// Self returns the cgroup this process is in, read from /proc/self/cgroup.
// On a pure cgroup v2 system the file is a single line: "0::/path".
func Self() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(data))
	rel, ok := strings.CutPrefix(line, "0::")
	if !ok {
		return "", fmt.Errorf("unexpected /proc/self/cgroup %q (not cgroup v2?)", line)
	}
	return filepath.Join(Root, rel), nil
}

// Delegated reports whether we own our current cgroup. Only then may we
// create sub-cgroups and move processes between them. The kernel requires
// write access to the common ancestor of the source and destination.
func Delegated() (bool, error) {
	dir, err := Self()
	if err != nil {
		return false, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return false, err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid) == os.Getuid(), nil
}

// Create makes a cgroup for container id inside our (delegated) cgroup and
// applies the limits. The resulting layout is:
//
//	<our scope>/              controllers enabled for children, no processes
//	<our scope>/supervisor/   minibox itself
//	<our scope>/<id>/         the container, with the limits
//
// The supervisor leaf exists because of cgroup v2's "no internal processes"
// rule: a cgroup that enables controllers for its children may not contain
// processes itself. So we first move out of our own cgroup.
func Create(id string, l Limits) (*Cgroup, error) {
	parent, err := Self()
	if err != nil {
		return nil, err
	}
	if ok, err := Delegated(); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("%w (%s)", ErrNotDelegated, parent)
	}

	if err := moveSelfTo(filepath.Join(parent, "supervisor")); err != nil {
		return nil, fmt.Errorf("move minibox to supervisor cgroup: %w", err)
	}
	if err := enableControllers(parent); err != nil {
		return nil, err
	}

	c := &Cgroup{Path: filepath.Join(parent, id)}
	if err := os.Mkdir(c.Path, 0o755); err != nil {
		return nil, err
	}
	if err := c.apply(l); err != nil {
		c.Destroy()
		return nil, err
	}
	return c, nil
}

func moveSelfTo(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Writing a PID to cgroup.procs moves the whole process (all threads).
	return writeFile(dir, "cgroup.procs", strconv.Itoa(os.Getpid()))
}

func enableControllers(dir string) error {
	for _, c := range controllers {
		if err := writeFile(dir, "cgroup.subtree_control", "+"+c); err != nil {
			return fmt.Errorf("enable %s controller (is it delegated? run scripts/check-env.sh): %w", c, err)
		}
	}
	return nil
}

// apply writes each requested limit into the cgroup's control files.
func (c *Cgroup) apply(l Limits) error {
	if l.MemoryBytes > 0 {
		if err := writeFile(c.Path, "memory.max", strconv.FormatInt(l.MemoryBytes, 10)); err != nil {
			return err
		}
		// In cgroup v2, memory.max limits RAM only. Swap is limited
		// separately. Without this, a memory hog on a machine with swap
		// would be pushed to swap instead of being stopped.
		if err := writeFile(c.Path, "memory.swap.max", "0"); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if l.CPUs > 0 {
		v := fmt.Sprintf("%d %d", cpuQuota(l.CPUs), cpuPeriodUsec)
		if err := writeFile(c.Path, "cpu.max", v); err != nil {
			return err
		}
	}
	if l.Pids > 0 {
		if err := writeFile(c.Path, "pids.max", strconv.FormatInt(l.Pids, 10)); err != nil {
			return err
		}
	}
	return nil
}

// Open returns the cgroup directory opened for CLONE_INTO_CGROUP. Starting
// the child directly inside the cgroup (rather than moving it after fork)
// means the limits apply from its very first instruction. There is no
// window in which it could fork processes that escape the limit.
func (c *Cgroup) Open() (*os.File, error) {
	return os.OpenFile(c.Path, os.O_RDONLY|syscall.O_DIRECTORY, 0)
}

// Destroy kills anything still in the cgroup and removes it.
func (c *Cgroup) Destroy() error {
	// cgroup.kill (Linux 5.14+) SIGKILLs every process in the cgroup. The
	// PID namespace normally guarantees nothing is left, so this is a
	// belt-and-braces step.
	_ = writeFile(c.Path, "cgroup.kill", "1")

	// rmdir fails with EBUSY until the kernel has finished releasing the
	// last process, which can take a few milliseconds after it exits.
	var err error
	for range 100 {
		if err = os.Remove(c.Path); err == nil || os.IsNotExist(err) {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("remove cgroup %s: %w", c.Path, err)
}

func writeFile(dir, name, value string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(value), 0)
}

// readKeyValues parses flat-keyed files such as cpu.stat and memory.events:
// one "key value" pair per line.
func readKeyValues(path string) (map[string]int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := map[string]int64{}
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
	return m, s.Err()
}

func readInt(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
}

package security

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sort"

	"golang.org/x/sys/unix"
)

// Mode selects how much hardening a container gets.
type Mode string

const (
	// None: namespaces only. Container root keeps every capability in its
	// user namespace, no seccomp, nothing masked. Used as the "no
	// hardening" configuration in the Phase 6 evaluation.
	None Mode = "none"
	// Baseline: Docker-like defaults (Phase 4). Default capability set,
	// Docker's seccomp profile, masked/read-only /proc and /sys paths,
	// no_new_privs.
	Baseline Mode = "baseline"
	// Policy: least privilege from a generated policy file (Phase 5).
	// The policy's capabilities, a seccomp allowlist of only the observed
	// syscalls, and a read-only root except the policy's writable paths,
	// plus the baseline's masked paths and no_new_privs.
	Policy Mode = "policy"
)

// ParseMode validates a --security value ("" means baseline).
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "":
		return Baseline, nil
	case None, Baseline:
		return Mode(s), nil
	}
	return "", fmt.Errorf("invalid --security %q: want baseline or none (use --policy FILE for policy mode)", s)
}

// Config is the security part of a container's configuration. It is sent
// to the container's init as JSON along with the rest of the config.
type Config struct {
	Mode     Mode
	Caps     []string // capabilities to keep (baseline: DefaultCaps)
	Syscalls []string // policy mode: seccomp allowlist
	Writable []string // policy mode: paths that stay writable
}

// NewBaseline returns the Phase 4 configuration.
func NewBaseline() Config { return Config{Mode: Baseline, Caps: DefaultCaps} }

// NewFromPolicy returns a policy-mode configuration.
func NewFromPolicy(p *PolicyFile) Config {
	return Config{Mode: Policy, Caps: p.Capabilities, Syscalls: p.Syscalls, Writable: p.WritablePaths}
}

// alwaysAllowed are syscalls a policy filter allows even if the trace
// didn't see them:
//   - execve: the filter is installed *before* execve, so it must pass or
//     the command could never start.
//   - exit, exit_group: denying exit would make a process unkillable from
//     the inside; it would spin on EPERM.
//   - rt_sigreturn, restart_syscall: the kernel's own plumbing for signal
//     handlers and for resuming a syscall interrupted by a stop. A signal
//     that happened not to arrive while profiling must not crash the app.
//
// None of these gives a process any new ability.
var alwaysAllowed = []string{"execve", "exit", "exit_group", "rt_sigreturn", "restart_syscall"}

// SeccompFilter returns the filter for this configuration, or nil (none).
func (c *Config) SeccompFilter() (*Filter, error) {
	switch c.Mode {
	case Baseline:
		return DockerFilter(c.Caps)
	case Policy:
		return policyFilter(c.Syscalls, c.Caps), nil
	}
	return nil, nil
}

// nsCloneFlags are the clone flags that create namespaces (Docker's mask
// 0x7e020000: NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET).
const nsCloneFlags = 0x7e020000

// policyFilter builds a default-deny allowlist from the policy's syscalls.
//
// Allowing syscalls by name alone has one dangerous gap: clone. Programs
// clone all the time (threads, fork), but clone with CLONE_NEWUSER creates
// a user namespace, which needs no capability and makes the caller root
// with every capability again inside it. The Phase 6 attack suite found
// exactly this (the unshare attack succeeded under a name-only policy). So,
// as in Docker's profile, clone is only allowed without namespace flags,
// and clone3 (whose flags are in memory, out of seccomp's reach) gets
// ENOSYS so libc and Go fall back to clone. The profiler infers
// CAP_SYS_ADMIN when an app really does create namespaces; such a policy
// gets plain clone/clone3.
func policyFilter(syscalls, caps []string) *Filter {
	f := &Filter{Default: ActEPERM}
	restrictClone := !slices.Contains(caps, "CAP_SYS_ADMIN")
	seen := map[string]bool{}
	for _, name := range append(append([]string{}, alwaysAllowed...), syscalls...) {
		if seen[name] {
			continue
		}
		seen[name] = true
		if restrictClone && (name == "clone" || name == "clone3") {
			continue // added below
		}
		f.Rules = append(f.Rules, Rule{Name: name, Action: ActAllow})
	}
	if restrictClone && (seen["clone"] || seen["clone3"]) {
		f.Rules = append(f.Rules,
			Rule{Name: "clone", Action: ActAllow, Args: []ArgCmp{{Index: 0, Op: OpMaskedEQ, Value: nsCloneFlags, ValueTwo: 0}}},
			Rule{Name: "clone3", Action: Action{Errno: unix.ENOSYS}})
	}
	return f
}

// SetupFilesystem runs inside the container after pivot_root, while init
// still has CAP_SYS_ADMIN. It masks sensitive paths (baseline and policy)
// and, in policy mode, makes the root read-only except the writable paths.
func (c *Config) SetupFilesystem() error {
	if c.Mode == None {
		return nil
	}
	if c.Mode == Policy {
		if err := readonlyRoot(c.Writable); err != nil {
			return fmt.Errorf("read-only root: %w", err)
		}
	}
	return MaskPaths()
}

// readonlyRoot remounts "/" read-only, after first giving each writable
// path its own (read-write) bind mount. A remount only changes the one
// mount it is applied to, so the bind mounts, and /dev, /proc and /sys,
// keep their own flags. Writes through a writable bind still go to the
// overlay's upper layer, so the image stays untouched.
func readonlyRoot(writable []string) error {
	paths := append([]string{}, writable...)
	sort.Strings(paths) // parents before children
	for _, p := range paths {
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			// Created at runtime by the app; its parent is writable
			// (the profiler records that), so nothing to do.
			continue
		}
		if err := unix.Mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			return fmt.Errorf("bind %s: %w", p, err)
		}
	}
	return RemountReadonly("/")
}

// Lock is the last step before execve: set no_new_privs, drop
// capabilities and install the seccomp filter, in that order:
//   - no_new_privs first: seccomp requires it for unprivileged callers, and
//     it stops setuid/file-capability binaries from regaining privileges.
//   - capabilities next, while capset/prctl are certainly still allowed.
//   - seccomp last, because the allowlist may not include those syscalls.
//
// All three are per-thread, so the caller must have locked its goroutine
// to the OS thread that will call execve.
func (c *Config) Lock() error {
	if c.Mode == None {
		return nil
	}
	filter, err := c.SeccompFilter() // build before restricting anything
	if err != nil {
		return err
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := DropCaps(c.Caps); err != nil {
		return err
	}
	return filter.Install()
}

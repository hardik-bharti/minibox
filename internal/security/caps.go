package security

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// capNames lists Linux capabilities by number (include/uapi/linux/capability.h).
var capNames = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
	"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
	"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
	"CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
	"CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// DefaultCaps is Docker's default capability set (moby
// oci/caps/defaults.go). Everything else, notably CAP_SYS_ADMIN (mount,
// unshare, sethostname, ...), CAP_SYS_PTRACE, CAP_NET_ADMIN and
// CAP_SYS_MODULE, is dropped.
//
// Remember these are capabilities *inside our user namespace*: even
// CAP_SYS_ADMIN here only covers objects that namespace owns. Dropping them
// still matters, because each one exposes more kernel code to the container
// (e.g. mounting filesystems) and kernel bugs there have led to escapes.
var DefaultCaps = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD",
	"CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
}

// CapNumber returns the number of a capability name like "CAP_NET_RAW".
func CapNumber(name string) (int, error) {
	if i := slices.Index(capNames, strings.ToUpper(name)); i >= 0 {
		return i, nil
	}
	return 0, fmt.Errorf("unknown capability %q", name)
}

// ValidateCaps checks every name in caps.
func ValidateCaps(caps []string) error {
	for _, c := range caps {
		if _, err := CapNumber(c); err != nil {
			return err
		}
	}
	return nil
}

// lastCap is the highest capability the running kernel knows. Newer
// kernels may add capabilities we have no name for; we still drop them.
func lastCap() int {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			return n
		}
	}
	return len(capNames) - 1
}

// DropCaps reduces the calling thread to exactly the capabilities in keep,
// in a way that survives execve.
//
// A process has several capability sets. The two that matter here:
//   - bounding: the ceiling for anything gained at exec. When UID 0 execs a
//     program, the kernel gives it every capability in the bounding set, so
//     shrinking the effective set alone would be undone by the next exec.
//   - effective/permitted/inheritable: what we hold right now.
//
// So we first drop the unwanted capabilities from the bounding set (this
// needs CAP_SETPCAP, so it has to come first), then set the other three
// sets to keep, and clear the ambient set.
func DropCaps(keep []string) error {
	want := map[int]bool{}
	for _, name := range keep {
		n, err := CapNumber(name)
		if err != nil {
			return err
		}
		want[n] = true
	}
	for c := 0; c <= lastCap(); c++ {
		if !want[c] {
			if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil {
				return fmt.Errorf("drop %s from bounding set: %w", capName(c), err)
			}
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("clear ambient caps: %w", err)
	}

	// capset takes two 32-bit words per set (capabilities 0-31, 32-63).
	var data [2]unix.CapUserData
	for c := range want {
		data[c/32].Effective |= 1 << (c % 32)
	}
	for i := range data {
		data[i].Permitted = data[i].Effective
		data[i].Inheritable = data[i].Effective
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

func capName(c int) string {
	if c < len(capNames) {
		return capNames[c]
	}
	return fmt.Sprintf("cap_%d", c)
}

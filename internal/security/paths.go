package security

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// MaskedPaths are hidden from the container (same list as Docker). They
// either leak information about the host kernel (timer_list, sched_debug,
// kcore = kernel memory, keys = keyrings) or expose hardware
// (acpi, scsi, firmware).
var MaskedPaths = []string{
	"/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore",
	"/proc/keys", "/proc/latency_stats", "/proc/timer_list",
	"/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
	"/sys/firmware", "/sys/devices/virtual/powercap",
}

// ReadonlyPaths can be read but not written (same list as Docker). Writing
// /proc/sys could change kernel settings, /proc/sysrq-trigger can reboot or
// crash the machine, /proc/irq can move interrupts between CPUs.
var ReadonlyPaths = []string{
	"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
}

// MaskPaths applies MaskedPaths and ReadonlyPaths. It runs inside the
// container after pivot_root, while we still have CAP_SYS_ADMIN in our user
// namespace. Paths that don't exist on this kernel are skipped.
//
// Many of these files are already unreadable to us (owned by the real
// root), but not all: /proc/timer_list, for example, is world-readable.
// And /proc/sys entries for namespaced settings (e.g. net.ipv4.*) are
// writable by the namespace's root, which is us. Masking them all makes the
// result independent of each file's permissions.
func MaskPaths() error {
	for _, p := range MaskedPaths {
		if err := maskPath(p); err != nil {
			return fmt.Errorf("mask %s: %w", p, err)
		}
	}
	for _, p := range ReadonlyPaths {
		if err := BindReadonly(p); err != nil {
			return fmt.Errorf("make %s read-only: %w", p, err)
		}
	}
	return nil
}

// maskPath hides a file by bind-mounting /dev/null over it, or a directory
// by mounting an empty read-only tmpfs over it. Docker does the same.
func maskPath(p string) error {
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if fi.IsDir() {
		return unix.Mount("tmpfs", p, "tmpfs", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "size=0")
	}
	return unix.Mount("/dev/null", p, "", unix.MS_BIND, "")
}

// BindReadonly makes path p read-only in place: bind-mount it onto itself
// (creating a separate mount for just that subtree) and remount the new
// mount read-only. A remount inside a user namespace must keep the
// nosuid/nodev/noexec flags of the original mount (the kernel "locks"
// them), so we carry them over.
func BindReadonly(p string) error {
	if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := unix.Mount(p, p, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return err
	}
	var st unix.Statfs_t
	if err := unix.Statfs(p, &st); err != nil {
		return err
	}
	flags := uintptr(unix.MS_BIND | unix.MS_REMOUNT | unix.MS_RDONLY)
	flags |= lockedFlags(st.Flags)
	return unix.Mount("", p, "", flags, "")
}

// lockedFlags converts statfs ST_* flags into the matching MS_* mount
// flags that a remount must preserve.
func lockedFlags(st int64) uintptr {
	var f uintptr
	if st&unix.ST_NOSUID != 0 {
		f |= unix.MS_NOSUID
	}
	if st&unix.ST_NODEV != 0 {
		f |= unix.MS_NODEV
	}
	if st&unix.ST_NOEXEC != 0 {
		f |= unix.MS_NOEXEC
	}
	if st&unix.ST_RELATIME != 0 {
		f |= unix.MS_RELATIME
	}
	if st&unix.ST_NOATIME != 0 {
		f |= unix.MS_NOATIME
	}
	return f
}

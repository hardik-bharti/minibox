package container

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/hardik-bharti/minibox/internal/network"
)

// These functions run inside the child, after it has entered its new user
// and mount namespaces. "root" there is really our own UID, so they only
// succeed because the namespaces are ours. None of them affects the host.

// makeMountsPrivate stops mount events propagating between our new mount
// namespace and the host's. Without it, systemd's default "shared"
// propagation could leak our mounts out (or host mounts in).
func makeMountsPrivate() error {
	return unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, "")
}

// mountOverlay stacks a private writable layer (upper) over the image
// (lower). Reads fall through to the image; writes copy the file up into
// upper. The image is never modified, so many containers can share it.
func mountOverlay(c *Config) error {
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", c.Rootfs, c.upperDir(), c.workDir())
	if err := unix.Mount("overlay", c.mergedDir(), "overlay", 0, opts); err != nil {
		return fmt.Errorf("mount overlay: %w", err)
	}
	return nil
}

// hostDevices are the device nodes most programs expect. An unprivileged
// user cannot mknod device files, even inside a user namespace, so we
// bind-mount the host's nodes instead. That is the same approach rootless
// Podman uses. These devices are harmless: none of them gives access to
// hardware or to other processes.
var hostDevices = []string{"null", "zero", "full", "random", "urandom", "tty"}

// setupDev gives the container a minimal /dev on a fresh tmpfs, so it does
// not see the host's real /dev (disks, consoles, etc).
func setupDev(newRoot string) error {
	dev := filepath.Join(newRoot, "dev")
	if err := unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID|unix.MS_NOEXEC, "mode=755,size=64k"); err != nil {
		return fmt.Errorf("mount /dev tmpfs: %w", err)
	}
	for _, name := range hostDevices {
		target := filepath.Join(dev, name)
		// A bind mount needs an existing file to mount over.
		f, err := os.Create(target)
		if err != nil {
			return err
		}
		f.Close()
		if err := unix.Mount("/dev/"+name, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind /dev/%s: %w", name, err)
		}
	}
	// Standard symlinks that shells and libc rely on.
	links := map[string]string{
		"fd":     "/proc/self/fd",
		"stdin":  "/proc/self/fd/0",
		"stdout": "/proc/self/fd/1",
		"stderr": "/proc/self/fd/2",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dev, name)); err != nil {
			return err
		}
	}
	return nil
}

// pivotRoot makes newRoot the container's "/" and detaches the old root.
//
// We use pivot_root rather than chroot because chroot only changes how
// paths are resolved for this process. The old root stays mounted and can
// be escaped (for example with a second chroot plus "cd .."). pivot_root
// moves the old root to a subdirectory, and unmounting it removes the host
// filesystem from our mount namespace entirely.
func pivotRoot(newRoot string) error {
	// pivot_root requires new_root to be a mount point. The overlay already
	// is, but bind-mounting it onto itself makes this function work for any
	// directory.
	if err := unix.Mount(newRoot, newRoot, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("bind new root: %w", err)
	}
	putOld := filepath.Join(newRoot, ".oldroot")
	if err := os.MkdirAll(putOld, 0o700); err != nil {
		return err
	}
	if err := unix.PivotRoot(newRoot, putOld); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	// MNT_DETACH (lazy unmount) because the old root still has busy
	// submounts. It disappears from our view immediately.
	if err := unix.Unmount("/.oldroot", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount old root: %w", err)
	}
	return os.Remove("/.oldroot")
}

// mountProc mounts a new procfs at newRoot/proc. Because we are in a new
// PID namespace, it shows only the container's processes, and our command
// appears as PID 1.
//
// This must happen *before* pivotRoot. The kernel lets an unprivileged user
// namespace mount procfs only if a fully visible procfs is already present in
// its mount namespace (fs/namespace.c: mnt_already_visible). The rule stops
// a container from mounting a fresh /proc to get around paths the host
// deliberately hid. Once the old root is detached the host's /proc is gone
// and the mount fails with EPERM.
func mountProc(newRoot string) error {
	target := filepath.Join(newRoot, "proc")
	if err := os.MkdirAll(target, 0o555); err != nil {
		return err
	}
	flags := uintptr(unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV)
	if err := unix.Mount("proc", target, "proc", flags, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	return nil
}

// mountSys mounts a read-only sysfs at newRoot/sys.
//
// sysfs shows the network devices of the mounting process's network
// namespace, so the kernel only lets a user namespace mount it if that user
// namespace owns the current network namespace. That is why /sys only
// became possible once containers got their own network namespace (Phase
// 3). Like /proc, it must be mounted before pivot_root (same
// mnt_already_visible rule). Read-only because nothing in a container
// should be reconfiguring kernel objects through /sys.
func mountSys(newRoot string) error {
	target := filepath.Join(newRoot, "sys")
	if err := os.MkdirAll(target, 0o555); err != nil {
		return err
	}
	flags := uintptr(unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV)
	if err := unix.Mount("sysfs", target, "sysfs", flags, ""); err != nil {
		return fmt.Errorf("mount /sys: %w", err)
	}
	return nil
}

// writeResolvConf points the container's DNS at slirp4netns's forwarder in
// bridge mode. It writes through the overlay, so the change lands in the
// container's upper layer and the image is untouched. With --net=none there
// is no DNS server to point at, so the image's file (if any) is left alone.
func writeResolvConf(c *Config) error {
	if c.Net != network.Bridge {
		return nil
	}
	etc := filepath.Join(c.mergedDir(), "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(etc, "resolv.conf"), []byte(network.ResolvConf), 0o644)
}

package network

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// BringUpLoopback sets the "lo" interface UP. It runs inside the container.
//
// A new network namespace starts with lo present but DOWN, so even
// 127.0.0.1 is unreachable. Bringing it up is the same as `ip link set lo
// up`, done with the older ioctl interface (get flags, set IFF_UP, write
// flags back) because it needs no netlink library. We may do this as
// "root" in a user namespace because that namespace owns the network
// namespace, which gives us CAP_NET_ADMIN over it (and only over it).
func BringUpLoopback() error {
	// Any socket works as a handle for interface ioctls.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("get lo flags: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("set lo up: %w", err)
	}
	return nil
}

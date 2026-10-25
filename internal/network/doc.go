// Package network gives each container its own network namespace and,
// optionally, outbound access and published ports.
//
// Modes (--net):
//   - none:   a new network namespace with only the loopback interface. The
//     container can talk to itself on 127.0.0.1 and nothing else.
//   - bridge: the same namespace plus a tap0 interface wired to the outside
//     world by slirp4netns, a user-mode TCP/IP stack running as an ordinary
//     process on the host. It gives the container an IP (10.0.3.100), a
//     default gateway, DNS and NAT'd outbound access, and forwards published
//     host ports (-p) into the container.
//
// Why slirp4netns and not a veth pair + Linux bridge + iptables NAT: the
// host end of a veth, the bridge and the NAT rules all live in the *host's*
// network namespace, and changing it needs CAP_NET_ADMIN there, i.e. real
// root. minibox is rootless, so it uses the same approach as rootless Podman
// and Docker. docs/phase3-networking.md compares the two in detail.
package network

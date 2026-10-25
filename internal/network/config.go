package network

import (
	"fmt"
	"strconv"
	"strings"
)

// Mode is the value of --net.
type Mode string

const (
	None   Mode = "none"
	Bridge Mode = "bridge"
)

// ParseMode validates a --net value. The empty string means the default.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "":
		// Default to no network: least privilege. A container that needs
		// the network must ask for it, and the attack suite (Phase 6) then
		// starts from a closed network rather than an open one.
		return None, nil
	case None, Bridge:
		return Mode(s), nil
	}
	return "", fmt.Errorf("invalid --net %q: want none or bridge", s)
}

// Addresses inside the container in bridge mode. slirp4netns derives them
// from the CIDR: .100 is the container, .2 the gateway (the host), .3 a DNS
// forwarder. We don't use slirp's default 10.0.2.0/24 because VirtualBox's
// NAT network uses that same range for the VM itself, and seeing 10.0.2.15
// on both sides would be confusing in a demo.
const (
	CIDR        = "10.0.3.0/24"
	ContainerIP = "10.0.3.100"
	GatewayIP   = "10.0.3.2"
	DNSIP       = "10.0.3.3"
	TapName     = "tap0"
)

// ResolvConf is written to the container's /etc/resolv.conf in bridge mode.
// The host's own resolv.conf usually points at systemd-resolved on
// 127.0.0.53, which is the *host's* loopback and unreachable from the
// container's namespace, so we point at slirp's DNS forwarder instead.
const ResolvConf = "nameserver " + DNSIP + "\n"

// Port is one -p HOST:CONTAINER[/PROTO] mapping.
type Port struct {
	Host      int
	Container int
	Proto     string // "tcp" or "udp"
}

func (p Port) String() string { return fmt.Sprintf("%d:%d/%s", p.Host, p.Container, p.Proto) }

// ParsePort parses "8080:80", "8080:80/tcp" or "5353:53/udp".
func ParsePort(s string) (Port, error) {
	p := Port{Proto: "tcp"}
	spec := s
	if i := strings.IndexByte(spec, '/'); i >= 0 {
		p.Proto, spec = spec[i+1:], spec[:i]
		if p.Proto != "tcp" && p.Proto != "udp" {
			return Port{}, fmt.Errorf("port %q: protocol must be tcp or udp", s)
		}
	}
	host, ctr, ok := strings.Cut(spec, ":")
	if !ok {
		return Port{}, fmt.Errorf("port %q: want HOST:CONTAINER, e.g. 8080:80", s)
	}
	var err error
	if p.Host, err = parsePortNum(host); err != nil {
		return Port{}, fmt.Errorf("port %q: host %w", s, err)
	}
	if p.Container, err = parsePortNum(ctr); err != nil {
		return Port{}, fmt.Errorf("port %q: container %w", s, err)
	}
	return p, nil
}

func parsePortNum(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %q is not a number in 1-65535", s)
	}
	return n, nil
}

package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// readyTimeout bounds how long we wait for slirp4netns to configure tap0.
// It normally takes a few milliseconds.
const readyTimeout = 10 * time.Second

// Slirp is a running slirp4netns process serving one container.
type Slirp struct {
	cmd    *exec.Cmd
	exitW  *os.File      // closing this tells slirp4netns to exit
	output *bytes.Buffer // slirp4netns stdout+stderr, shown if setup fails
	socket string        // API socket path, used for port forwarding
}

// StartSlirp attaches slirp4netns to the network namespace of process pid
// (the container's init) and waits until tap0 is configured. Port mappings
// are installed before it returns, so the container's command never starts
// without its network. socketDir must be a private directory that is
// removed after the container exits (the container's state dir).
//
// How it works: slirp4netns joins the container's user and network
// namespaces just long enough to create tap0 there, then passes the tap
// file descriptor back to its process on the host. From then on, every
// packet the container sends to tap0 is read by slirp4netns, which
// re-creates the connection with ordinary host sockets (connect(), sendto()),
// i.e. NAT done in user space. Replies travel back the same way.
func StartSlirp(pid int, socketDir string, ports []Port) (*Slirp, error) {
	bin, err := exec.LookPath("slirp4netns")
	if err != nil {
		return nil, fmt.Errorf("--net=bridge needs slirp4netns (sudo apt install slirp4netns): %w", err)
	}

	// Two pipes: slirp4netns writes "1" to ready when tap0 is up, and
	// exits when exit becomes readable (we close our end, or we die and
	// the kernel closes it for us, so it can never outlive minibox).
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer readyR.Close()
	exitR, exitW, err := os.Pipe()
	if err != nil {
		readyW.Close()
		return nil, err
	}

	s := &Slirp{
		exitW:  exitW,
		output: &bytes.Buffer{},
		socket: filepath.Join(socketDir, "slirp.sock"),
	}
	s.cmd = exec.Command(bin,
		"--configure",                 // assign the IP, route and DNS inside the namespace
		"--mtu=65520",                 // large MTU: fewer trips through slirp per byte (Podman default)
		"--cidr="+CIDR,                // see the CIDR comment in config.go
		"--disable-host-loopback",     // the container must not reach the host's 127.0.0.1 services
		"--enable-sandbox",            // slirp4netns pivots into an empty root of its own...
		"--enable-seccomp",            // ...and filters its own syscalls, limiting damage if a packet exploits it
		"--api-socket="+s.socket,      // control socket for port forwarding
		"--ready-fd=3", "--exit-fd=4", // ExtraFiles[0] and [1] below
		strconv.Itoa(pid), TapName)
	s.cmd.ExtraFiles = []*os.File{readyW, exitR}
	s.cmd.Stdout, s.cmd.Stderr = s.output, s.output
	// Own process group: a Ctrl-C in the terminal goes to the foreground
	// group, and we want minibox (not the tty) to decide when the network
	// goes away, after the container has exited.
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = s.cmd.Start()
	readyW.Close() // the child has its own copies now
	exitR.Close()
	if err != nil {
		exitW.Close()
		return nil, fmt.Errorf("start slirp4netns: %w", err)
	}

	if err := s.waitReady(readyR); err != nil {
		s.Stop()
		return nil, err
	}
	for _, p := range ports {
		if err := s.addPort(p); err != nil {
			s.Stop()
			return nil, fmt.Errorf("publish %s: %w", p, err)
		}
	}
	return s, nil
}

// waitReady blocks until slirp4netns reports tap0 is configured. If it dies
// first, its end of the pipe closes and we read EOF instead.
func (s *Slirp) waitReady(readyR *os.File) error {
	readyR.SetReadDeadline(time.Now().Add(readyTimeout))
	buf := make([]byte, 1)
	if _, err := readyR.Read(buf); err != nil {
		return fmt.Errorf("slirp4netns did not become ready (%v): %s", err, strings.TrimSpace(s.output.String()))
	}
	return nil
}

// apiRequest is the JSON command format of slirp4netns's API socket
// (modelled on QEMU's QMP).
type apiRequest struct {
	Execute   string `json:"execute"`
	Arguments any    `json:"arguments"`
}

type hostfwd struct {
	Proto     string `json:"proto"`
	HostAddr  string `json:"host_addr"`
	HostPort  int    `json:"host_port"`
	GuestAddr string `json:"guest_addr"`
	GuestPort int    `json:"guest_port"`
}

// addPort asks slirp4netns to listen on the host port and forward each
// connection to the container. It listens on all host addresses, like
// `docker run -p`. Host ports below 1024 need root, so they fail here.
func (s *Slirp) addPort(p Port) error {
	req := apiRequest{"add_hostfwd", hostfwd{
		Proto: p.Proto, HostAddr: "0.0.0.0", HostPort: p.Host,
		GuestAddr: ContainerIP, GuestPort: p.Container,
	}}
	conn, err := net.Dial("unix", s.socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(readyTimeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	// slirp4netns handles one request per connection and answers once we
	// signal the end of the request.
	conn.(*net.UnixConn).CloseWrite()
	reply, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	var resp struct {
		Error *struct {
			Desc string `json:"desc"`
		} `json:"error"`
	}
	if err := json.Unmarshal(reply, &resp); err != nil {
		return fmt.Errorf("bad reply %q: %w", reply, err)
	}
	if resp.Error != nil {
		// slirp gives no reason; a busy port or one below 1024 are the
		// usual causes.
		return fmt.Errorf("%s (host port in use, or below 1024?)", resp.Error.Desc)
	}
	return nil
}

// Stop shuts slirp4netns down and waits for it to exit.
func (s *Slirp) Stop() {
	s.exitW.Close()
	done := make(chan struct{})
	go func() { s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// Should not happen, but never let a stuck helper hang minibox.
		s.cmd.Process.Kill()
		<-done
	}
}

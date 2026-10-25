package container

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hardik-bharti/minibox/internal/cgroups"
	"github.com/hardik-bharti/minibox/internal/network"
)

// Config describes one container. The parent fills it in and sends it to
// the child (init) process as JSON over a pipe, so every field is exported.
type Config struct {
	ID       string       // random hex ID, also the default hostname
	Rootfs   string       // absolute path to the image; becomes the read-only overlay lower layer
	Command  []string     // program and arguments to exec inside the container
	Hostname string       // hostname inside the new UTS namespace
	StateDir string       // per-container dir holding the overlay upper/work/merged dirs
	Net      network.Mode // none: loopback only; bridge: slirp4netns outbound access

	// Limits are applied by the parent (host side) via cgroups. The child
	// never needs them, so they are not sent over the config pipe.
	Limits cgroups.Limits `json:"-"`
	// WantCgroup creates a cgroup even with no limits, for usage stats.
	WantCgroup bool `json:"-"`
	// Ports are host->container forwards, set up by the parent through
	// slirp4netns (bridge mode only).
	Ports []network.Port `json:"-"`
}

// Overlay directory layout inside StateDir.
func (c *Config) upperDir() string  { return filepath.Join(c.StateDir, "upper") }
func (c *Config) workDir() string   { return filepath.Join(c.StateDir, "work") }
func (c *Config) mergedDir() string { return filepath.Join(c.StateDir, "merged") }

// NewConfig validates user input and builds a Config with a fresh ID.
// It does not touch the filesystem apart from checking that the rootfs exists.
func NewConfig(rootfs string, command []string, hostname, stateRoot string) (*Config, error) {
	if len(command) == 0 {
		return nil, errors.New("no command given")
	}

	// overlayfs wants absolute paths, and we chdir later, so resolve now.
	abs, err := filepath.Abs(rootfs)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("rootfs: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("rootfs %s is not a directory", abs)
	}

	id, err := newID()
	if err != nil {
		return nil, err
	}
	if hostname == "" {
		hostname = id
	}
	return &Config{
		ID:       id,
		Rootfs:   abs,
		Command:  command,
		Hostname: hostname,
		StateDir: filepath.Join(stateRoot, id),
		Net:      network.None,
	}, nil
}

// newID returns 12 random hex characters, the same length as Docker's short IDs.
func newID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// DefaultStateRoot is where per-container directories are created. We use
// the user's data dir (on disk) rather than /run/user (tmpfs, i.e. RAM) so
// that a container writing large files cannot exhaust memory through its
// overlay upper layer. MINIBOX_ROOT overrides it, e.g. for tests.
func DefaultStateRoot() (string, error) {
	if dir := os.Getenv("MINIBOX_ROOT"); dir != "" {
		return filepath.Abs(dir)
	}
	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "minibox", "containers"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "share", "minibox", "containers"), nil
}

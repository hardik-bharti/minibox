package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hardik-bharti/minibox/internal/network"
)

// configFD is the file descriptor on which the child receives its Config.
// ExtraFiles[0] in the parent becomes fd 3 in the child (after stdin, stdout
// and stderr).
const configFD = 3

// containerPath is the PATH the command sees. We don't inherit the host's
// PATH because it may name directories that don't exist in the image.
const containerPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Init is the container side of `minibox run`. It runs as a re-executed copy
// of minibox (`minibox init`) that is already inside the new namespaces and
// is PID 1 there. It builds the container's filesystem view and then execs
// the user's command, which replaces this process (so the command becomes
// PID 1). Init only returns if something failed.
func Init() error {
	// Capabilities, no_new_privs and seccomp filters belong to a thread,
	// not a process. Stay on one OS thread so the restrictions we set up
	// are on the same thread that finally calls execve. We never unlock:
	// on success this process becomes the user's command.
	runtime.LockOSThread()

	c, err := readConfig()
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	steps := []struct {
		name string
		fn   func() error
	}{
		{"make mounts private", makeMountsPrivate},
		{"mount overlay", func() error { return mountOverlay(c) }},
		{"write /etc/resolv.conf", func() error { return writeResolvConf(c) }},
		{"mount volumes", func() error { return mountVolumes(c) }},
		{"set up /dev", func() error { return setupDev(c.mergedDir()) }},
		{"mount /proc", func() error { return mountProc(c.mergedDir()) }}, // must precede pivot_root
		{"mount /sys", func() error { return mountSys(c.mergedDir()) }},   // must precede pivot_root
		{"pivot_root", func() error { return pivotRoot(c.mergedDir()) }},
		{"set hostname", func() error { return unix.Sethostname([]byte(c.Hostname)) }},
		{"bring up loopback", network.BringUpLoopback},
		{"harden filesystem", c.Security.SetupFilesystem}, // needs CAP_SYS_ADMIN: before Lock
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return execCommand(c)
}

// readConfig reads the JSON Config the parent wrote to our pipe. We use a
// pipe instead of command-line arguments or environment variables so that
// nothing about the config is visible in the container's /proc/1/cmdline or
// environment once we exec.
func readConfig() (*Config, error) {
	f := os.NewFile(configFD, "config-pipe")
	defer f.Close() // close before exec so the command doesn't inherit fd 3
	var c Config
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// execCommand replaces this process with the user's command, using a clean
// environment. After exec there is no minibox code left in the container.
func execCommand(c *Config) error {
	env := []string{
		"PATH=" + containerPath,
		"HOME=/root",
		"HOSTNAME=" + c.Hostname,
	}
	if term := os.Getenv("TERM"); term != "" {
		env = append(env, "TERM="+term)
	}

	// LookPath searches $PATH, so point it at the container's PATH first.
	// We are already pivoted, so this resolves inside the container's root.
	os.Setenv("PATH", containerPath)
	path, err := exec.LookPath(c.Command[0])
	if err != nil {
		return err
	}
	// Last step: no_new_privs, drop capabilities, install seccomp. After
	// this we can't do any more setup, so nothing but execve may follow.
	if err := c.Security.Lock(); err != nil {
		return fmt.Errorf("apply security: %w", err)
	}
	return syscall.Exec(path, c.Command, env)
}

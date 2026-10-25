package container

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
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
		{"set up /dev", func() error { return setupDev(c.mergedDir()) }},
		{"mount /proc", func() error { return mountProc(c.mergedDir()) }}, // must precede pivot_root
		{"pivot_root", func() error { return pivotRoot(c.mergedDir()) }},
		{"set hostname", func() error { return unix.Sethostname([]byte(c.Hostname)) }},
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
	return syscall.Exec(path, c.Command, env)
}

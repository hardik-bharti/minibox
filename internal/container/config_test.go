package container

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

func TestNewConfig(t *testing.T) {
	rootfs := t.TempDir()
	stateRoot := t.TempDir()

	c, err := NewConfig(rootfs, []string{"sh", "-c", "true"}, "", stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(c.ID) {
		t.Errorf("ID %q is not 12 hex chars", c.ID)
	}
	if c.Hostname != c.ID {
		t.Errorf("default hostname = %q, want the ID %q", c.Hostname, c.ID)
	}
	if c.StateDir != filepath.Join(stateRoot, c.ID) {
		t.Errorf("StateDir = %q, want it under %q", c.StateDir, stateRoot)
	}
	if !filepath.IsAbs(c.Rootfs) {
		t.Errorf("Rootfs %q should be absolute", c.Rootfs)
	}
}

func TestNewConfigRelativeRootfsBecomesAbsolute(t *testing.T) {
	// overlayfs options need absolute paths, and init chdirs away.
	c, err := NewConfig(".", []string{"true"}, "h", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(c.Rootfs) {
		t.Errorf("Rootfs %q should be absolute", c.Rootfs)
	}
	if c.Hostname != "h" {
		t.Errorf("Hostname = %q, want %q", c.Hostname, "h")
	}
}

func TestNewConfigErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)

	cases := map[string]struct {
		rootfs string
		cmd    []string
	}{
		"no command":       {t.TempDir(), nil},
		"missing rootfs":   {"/does/not/exist", []string{"sh"}},
		"rootfs not a dir": {file, []string{"sh"}},
	}
	for name, tc := range cases {
		if _, err := NewConfig(tc.rootfs, tc.cmd, "", t.TempDir()); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("duplicate ID %s", id)
		}
		seen[id] = true
	}
}

func TestDefaultStateRoot(t *testing.T) {
	t.Setenv("MINIBOX_ROOT", "")
	t.Setenv("XDG_DATA_HOME", "/data")
	if got, _ := DefaultStateRoot(); got != "/data/minibox/containers" {
		t.Errorf("with XDG_DATA_HOME: got %q", got)
	}
	t.Setenv("MINIBOX_ROOT", "/custom")
	if got, _ := DefaultStateRoot(); got != "/custom" {
		t.Errorf("MINIBOX_ROOT should win: got %q", got)
	}
}

// overlayfs leaves work/work with mode 000, and containers can create
// unreadable dirs too. removeStateDir must still delete everything.
func TestRemoveStateDirHandlesUnreadableDirs(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ctr")
	locked := filepath.Join(dir, "work", "work")
	if err := os.MkdirAll(filepath.Join(locked, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(locked, "inner", "f"), []byte("x"), 0o000)
	os.Chmod(filepath.Join(locked, "inner"), 0o000)
	os.Chmod(locked, 0o000)

	if err := removeStateDir(dir); err != nil {
		t.Fatalf("removeStateDir: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("dir still exists (stat err = %v)", err)
	}
}

func TestExitCode(t *testing.T) {
	cases := []struct {
		script string
		want   int
	}{
		{"exit 0", 0},
		{"exit 42", 42},
		{"kill -KILL $$", 128 + 9}, // killed by signal -> 128+N
	}
	for _, tc := range cases {
		got, err := exitCode(exec.Command("sh", "-c", tc.script).Run())
		if err != nil {
			t.Fatalf("%q: %v", tc.script, err)
		}
		if got != tc.want {
			t.Errorf("%q: exit code %d, want %d", tc.script, got, tc.want)
		}
	}
}

func TestParseVolume(t *testing.T) {
	dir := t.TempDir()
	v, err := ParseVolume(dir + ":/data:ro")
	if err != nil || v.Host != dir || v.Container != "/data" || !v.ReadOnly {
		t.Errorf("ParseVolume ro = %+v, %v", v, err)
	}
	if v, err := ParseVolume(dir + ":/data/"); err != nil || v.ReadOnly || v.Container != "/data" {
		t.Errorf("ParseVolume rw = %+v, %v", v, err)
	}
	for _, bad := range []string{dir, dir + ":data", dir + ":/", "/does/not/exist:/x", dir + ":/x:rx", dir + ":/x:ro:extra"} {
		if _, err := ParseVolume(bad); err == nil {
			t.Errorf("ParseVolume(%q) accepted", bad)
		}
	}
}

package container

import (
	"io/fs"
	"os"
	"path/filepath"
)

// createStateDir makes the per-container upper/work/merged directories.
// 0700 because the upper layer holds everything the container writes.
func createStateDir(c *Config) error {
	for _, d := range []string{c.upperDir(), c.workDir(), c.mergedDir()} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// removeStateDir deletes a container's directory after it has exited.
//
// A plain os.RemoveAll is not enough: overlayfs creates work/work with mode
// 000, and a container may create unreadable directories in its upper layer.
// We own every file (our UID is the only one mapped into the container), so
// we can always chmod a directory to make its contents deletable.
func removeStateDir(dir string) error {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if d != nil && d.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		// WalkDir calls us for a directory *before* reading its entries,
		// so the chmod above lands in time. Ignore errors and let
		// RemoveAll report anything that is really wrong.
		return nil
	})
	return os.RemoveAll(dir)
}

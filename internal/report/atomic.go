package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/TGPSKI/skeptic/internal/model"
)

// WriteFileAtomic writes data to path via a temporary file in the same
// directory followed by a rename, so a reader never observes a partial report.
// Same-directory is required: rename is only atomic within a filesystem.
//
// Parent directories are created when missing.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	abs, err := filepath.Abs(model.ExpandHomePath(path))
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(abs)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup: a successful rename makes this a no-op.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		if cerr := tmp.Close(); cerr != nil {
			return fmt.Errorf("write %s: %w (close: %v)", tmpName, err, cerr)
		}
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	// Chmod before rename so the file is never briefly visible at the wrong mode.
	if err := tmp.Chmod(perm); err != nil {
		if cerr := tmp.Close(); cerr != nil {
			return fmt.Errorf("chmod %s: %w (close: %v)", tmpName, err, cerr)
		}
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, abs); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, abs, err)
	}
	return nil
}

package corpus

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	corpusMarkerFile = ".skeptic-corpus-lock"
	corpusKeyFile    = ".corpus-key"
	corpusFetchLock  = ".corpus-fetch.lock"
	corpusManifest   = "corpus.lock"
	artifactsDir     = "artifacts"
)

var agentIgnoreFiles = []string{
	".gitignore",
	".cursorignore",
	".copilotignore",
	".ai-ignore",
}

var forbiddenPathComponents = map[string]struct{}{
	"node_modules":   {},
	"vendor":         {},
	"venv":           {},
	".venv":          {},
	"site-packages":  {},
	"__pypackages__": {},
	".tox":           {},
}

// UserDataDir returns the XDG data directory for persistent user data.
// Linux: $XDG_DATA_HOME (default ~/.local/share)
// macOS: ~/Library/Application Support
// Windows: os.UserConfigDir() (%AppData%)
func UserDataDir() (string, error) {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return xdg, nil
	}
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("corpus: user data dir: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support"), nil
	case "windows":
		return os.UserConfigDir()
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("corpus: user data dir: %w", err)
		}
		return filepath.Join(home, ".local", "share"), nil
	}
}

// DefaultCorpusPath returns the platform default corpus location.
func DefaultCorpusPath() (string, error) {
	dataDir, err := UserDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "skeptic", "corpus"), nil
}

// ResolveCorpusPath determines the corpus path from flag, config, or default.
// configValues is the flat map from .skeptic.json (may be nil).
func ResolveCorpusPath(flagPath string, configValues map[string]string) (string, error) {
	raw := flagPath
	if raw == "" {
		if configValues != nil {
			if cp, ok := configValues["corpus-path"]; ok && cp != "" {
				raw = cp
			}
			if raw == "" {
				if cp, ok := configValues["corpus_path"]; ok && cp != "" {
					raw = cp
				}
			}
		}
	}
	if raw == "" {
		return DefaultCorpusPath()
	}
	return raw, nil
}

// ResolvePath converts a path to an absolute, symlink-resolved path.
func ResolvePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("corpus: resolve path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return abs, nil
		}
		return "", fmt.Errorf("corpus: resolve path: %w", err)
	}
	return resolved, nil
}

// ValidateCorpusPath checks that the resolved absolute path is safe for corpus storage.
// It rejects paths inside git worktrees, MCP allowed roots, dependency/vendor
// environments, and scan targets.
func ValidateCorpusPath(resolved string, scanTargets []string, mcpRoots []string) error {
	if err := checkGitWorktree(resolved); err != nil {
		return err
	}
	if err := checkMCPRoots(resolved, mcpRoots); err != nil {
		return err
	}
	if err := checkVendorPath(resolved); err != nil {
		return err
	}
	if err := checkScanTargetOverlap(resolved, scanTargets); err != nil {
		return err
	}
	return nil
}

func checkGitWorktree(resolved string) error {
	dir := resolved
	for {
		gitPath := filepath.Join(dir, ".git")
		if info, err := os.Lstat(gitPath); err == nil {
			if info.IsDir() || info.Mode().IsRegular() {
				return fmt.Errorf("corpus: path %q is inside git worktree (found %s)", resolved, gitPath)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil
}

func checkMCPRoots(resolved string, mcpRoots []string) error {
	for _, root := range mcpRoots {
		rootResolved, err := ResolvePath(root)
		if err != nil {
			continue
		}
		if hasPathPrefix(resolved, rootResolved) || hasPathPrefix(rootResolved, resolved) {
			return fmt.Errorf("corpus: path %q overlaps MCP allowed root %q", resolved, root)
		}
	}
	return nil
}

func checkVendorPath(resolved string) error {
	parts := strings.Split(resolved, string(filepath.Separator))
	for _, part := range parts {
		if _, forbidden := forbiddenPathComponents[part]; forbidden {
			return fmt.Errorf("corpus: path %q contains dependency/vendor component %q", resolved, part)
		}
	}
	return nil
}

func checkScanTargetOverlap(resolved string, scanTargets []string) error {
	for _, target := range scanTargets {
		targetResolved, err := ResolvePath(target)
		if err != nil {
			continue
		}
		if hasPathPrefix(resolved, targetResolved) || hasPathPrefix(targetResolved, resolved) {
			return fmt.Errorf("corpus: path %q overlaps scan target %q", resolved, target)
		}
	}
	return nil
}

// hasPathPrefix reports whether child is equal to or under parent.
func hasPathPrefix(child, parent string) bool {
	if child == parent {
		return true
	}
	prefix := parent + string(filepath.Separator)
	return strings.HasPrefix(child, prefix)
}

// WriteMarkerFiles creates the corpus marker and agent ignore files.
func WriteMarkerFiles(corpusRoot string) error {
	marker := filepath.Join(corpusRoot, corpusMarkerFile)
	if err := os.WriteFile(marker, []byte("skeptic corpus — do not scan\n"), 0644); err != nil {
		return fmt.Errorf("corpus: write marker: %w", err)
	}
	for _, name := range agentIgnoreFiles {
		path := filepath.Join(corpusRoot, name)
		if err := os.WriteFile(path, []byte("*\n"), 0644); err != nil {
			return fmt.Errorf("corpus: write %s: %w", name, err)
		}
	}
	return nil
}

// AcquireFlock acquires a non-blocking exclusive lock on the given path.
// Returns the open file for use with ReleaseFlock. The locking primitive is
// platform-specific; see flock_unix.go and flock_windows.go.
func AcquireFlock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("corpus: flock open: %w", err)
	}
	if err := lockFileExclusive(f); err != nil {
		if cerr := f.Close(); cerr != nil {
			return nil, fmt.Errorf("corpus: flock %s failed: %w (close: %v)", path, err, cerr)
		}
		return nil, fmt.Errorf("corpus: another corpus operation is in progress (flock %s): %w", path, err)
	}
	return f, nil
}

// ReleaseFlock releases the advisory lock and closes the file.
func ReleaseFlock(f *os.File) {
	if f == nil {
		return
	}
	if err := unlockFile(f); err != nil {
		fmt.Fprintf(os.Stderr, "warning: flock unlock: %v\n", err)
	}
	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: close lock file: %v\n", err)
	}
}

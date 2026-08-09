// Package pathfilter holds the --ignore-paths matching rules.
//
// It exists as its own package because two independent walkers consult it:
// internal/scan walks the tree for rule matches, and internal/checks walks it
// again for identity-graph analysis. internal/scan imports internal/checks, so
// the matcher cannot live in either without a cycle. One implementation means
// the two walkers cannot disagree about what "ignored" means.
package pathfilter

import (
	"path/filepath"
	"strings"
)

// Matches reports whether relPath should be skipped, for a file or a directory
// under a scan root. Patterns support filepath.Match globs, optional **
// segments, basename-only matches, and simple path prefixes such as "vendor/".
//
// relPath must be relative to the scan root. An absolute path will not match a
// repo-relative pattern.
func Matches(relPath string, patterns []string) bool {
	relPath = filepath.ToSlash(relPath)
	base := filepath.Base(relPath)
	for _, raw := range patterns {
		pattern := filepath.ToSlash(strings.TrimSpace(raw))
		if pattern == "" {
			continue
		}
		if strings.Contains(pattern, "**") {
			if matchesDoubleStar(relPath, pattern) {
				return true
			}
			continue
		}
		matched, err := filepath.Match(pattern, relPath)
		if err == nil && matched {
			return true
		}
		matched, err = filepath.Match(pattern, base)
		if err == nil && matched {
			return true
		}
		if strings.HasPrefix(relPath, pattern) {
			return true
		}
	}
	return false
}

func matchesDoubleStar(path, pattern string) bool {
	for strings.Contains(pattern, "**/**") {
		pattern = strings.ReplaceAll(pattern, "**/**", "**")
	}
	if strings.HasPrefix(pattern, "**/") {
		return matchesFromAnySegment(path, pattern[3:])
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		if prefix == "" {
			return true
		}
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	idx := strings.Index(pattern, "**")
	if idx < 0 {
		return false
	}
	left := strings.Trim(pattern[:idx], "/")
	right := strings.Trim(pattern[idx+2:], "/")
	rest := path
	if left != "" {
		if path == left {
			rest = ""
		} else if strings.HasPrefix(path, left+"/") {
			rest = path[len(left)+1:]
		} else {
			return false
		}
	}
	if right == "" {
		return true
	}
	return matchesFromAnySegment(rest, right)
}

func matchesFromAnySegment(path, suffix string) bool {
	if suffix == "" {
		return true
	}
	for {
		matched, err := filepath.Match(suffix, path)
		if err == nil && matched {
			return true
		}
		i := strings.Index(path, "/")
		if i < 0 {
			return false
		}
		path = path[i+1:]
	}
}

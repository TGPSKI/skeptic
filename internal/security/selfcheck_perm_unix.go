//go:build !windows

package security

import "io/fs"

// isWorldWritable reads the POSIX other-write bit.
func isWorldWritable(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o002 != 0
}

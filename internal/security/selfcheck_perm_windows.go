//go:build windows

package security

import "io/fs"

// isWorldWritable always reports false on Windows.
//
// Windows has no POSIX mode bits. Go synthesizes FileMode from the read-only
// file attribute alone: 0666 for a writable file, 0444 for a read-only one.
// Every writable file therefore has the other-write bit set, so reading
// Perm()&0o002 reports every artifact as world-writable rather than the ones
// with a permissive ACL.
//
// Answering the real question means reading the DACL through advapi32, which
// needs golang.org/x/sys/windows. skeptic is stdlib-only, so this reports
// nothing rather than reporting noise. Callers on Windows get no signal from
// this check, not a wrong one.
func isWorldWritable(_ fs.FileInfo) bool {
	return false
}

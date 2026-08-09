//go:build !windows

package corpus

import (
	"os"
	"syscall"
)

// lockFileExclusive takes a non-blocking exclusive advisory lock. It returns an
// error rather than waiting when another process holds the lock, so a second
// corpus operation fails fast instead of hanging.
func lockFileExclusive(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

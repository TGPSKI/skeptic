//go:build windows

package corpus

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Windows has no flock(2), and the standard library's syscall package does not
// export LockFileEx on Windows, so it is resolved from kernel32.dll at run time.
// syscall.NewLazyDLL, syscall.SyscallN, and unsafe are all standard library, so
// the stdlib-only constraint holds.
//
// Locking the full 64-bit byte range reproduces flock's whole-file semantics.
//
// The unsafe.Pointer -> uintptr conversion is written inline in the SyscallN
// argument list. That is the one form the compiler recognises as keeping the
// pointer alive across the call (unsafe.Pointer rule 4). LazyProc.Call would
// not qualify: it takes ...uintptr, so the conversion happens in the caller's
// frame and the referent could move before the syscall reads it.
const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
	lockRangeLow            = ^uint32(0)
	lockRangeHigh           = ^uint32(0)
)

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

// lockFileExclusive takes a non-blocking exclusive lock, matching the Unix
// LOCK_EX|LOCK_NB behavior: fail immediately rather than wait.
func lockFileExclusive(f *os.File) error {
	if err := procLockFileEx.Find(); err != nil {
		return fmt.Errorf("resolve LockFileEx: %w", err)
	}
	var overlapped syscall.Overlapped
	r1, _, errno := syscall.SyscallN(
		procLockFileEx.Addr(),
		f.Fd(),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0,
		uintptr(lockRangeLow),
		uintptr(lockRangeHigh),
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r1 == 0 {
		return errnoErr(errno)
	}
	return nil
}

func unlockFile(f *os.File) error {
	if err := procUnlockFileEx.Find(); err != nil {
		return fmt.Errorf("resolve UnlockFileEx: %w", err)
	}
	var overlapped syscall.Overlapped
	r1, _, errno := syscall.SyscallN(
		procUnlockFileEx.Addr(),
		f.Fd(),
		0,
		uintptr(lockRangeLow),
		uintptr(lockRangeHigh),
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r1 == 0 {
		return errnoErr(errno)
	}
	return nil
}

// errnoErr guards against a zero errno on a reported failure, which would
// otherwise surface as a nil error and be read as success.
func errnoErr(errno syscall.Errno) error {
	if errno == 0 {
		return syscall.EINVAL
	}
	return errno
}

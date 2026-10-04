//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package logserver

import (
	"fmt"
	"os"
	"syscall"
)

// lockLog takes an exclusive advisory lock on the log file for as long as it is
// open, so a second server on the same directory fails to start instead of
// overwriting the first one's entries.
func lockLog(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("logserver: %s is in use by another process: %w", f.Name(), err)
	}
	return nil
}

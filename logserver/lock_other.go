//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package logserver

import "os"

// lockLog does nothing on this platform: run one server per directory.
func lockLog(*os.File) error { return nil }

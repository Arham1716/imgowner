// Package securedir prepares directories that only the current user can
// reach. The scan cache and the scan history both keep data that decides what
// imgowner reports, so a directory another account can write to is never used.
package securedir

import (
	"errors"
	"fmt"
	"os"
)

// ErrUnsafe is wrapped by every refusal to use a directory, so callers can
// tell "someone else controls this path" apart from ordinary I/O errors.
var ErrUnsafe = errors.New("directory is not safe to use")

// Ensure creates dir (and its parents) if needed and guarantees that only the
// current user can read or write it:
//
//   - a symbolic link is refused, so the data can't be redirected elsewhere;
//   - on POSIX a directory owned by another user is refused, and one with
//     group/world permission bits is tightened to 0700;
//   - on Windows the directory gets a protected, owner-only ACL.
//
// A directory someone else created first (the shared-/tmp attack) therefore
// fails here instead of being trusted.
func Ensure(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspecting %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symbolic link", ErrUnsafe, dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafe, dir)
	}
	return restrict(dir, info)
}

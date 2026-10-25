//go:build !windows

package securedir

import (
	"fmt"
	"os"
	"syscall"
)

// restrict refuses a directory owned by another user and tightens group/world
// permission bits on one the current user owns. MkdirAll leaves an existing
// directory's owner and mode alone, which is exactly what an attacker who
// creates the path first relies on.
func restrict(dir string, info os.FileInfo) error {
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s belongs to another user (uid %d)", ErrUnsafe, dir, st.Uid)
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("%w: %s is accessible to other users and could not be restricted: %v", ErrUnsafe, dir, err)
		}
	}
	return nil
}

//go:build !windows

package history

// restrictToOwner is a no-op off Windows: POSIX owner-only access is enforced
// with the 0700 directory and 0600 file modes set in Open and Append.
func restrictToOwner(string) error { return nil }

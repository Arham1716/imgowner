package securedir

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsure_CreatesMissingDirectoryOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := Ensure(dir); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("directory not created: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Errorf("mode %o, want 0700", info.Mode().Perm())
	}
}

func TestEnsure_TightensAWorldWritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits; Windows ACLs are covered by the history tests")
	}
	dir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { // defeat the umask
		t.Fatal(err)
	}
	if err := Ensure(dir); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	info, _ := os.Stat(dir)
	if info.Mode().Perm() != 0o700 {
		t.Errorf("mode %o after Ensure, want 0700", info.Mode().Perm())
	}
}

// A symlink could point the data at a directory someone else reads.
func TestEnsure_RefusesASymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if err := Ensure(link); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Ensure(symlink) = %v, want ErrUnsafe", err)
	}
}

func TestEnsure_RefusesAFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(f); err == nil {
		t.Fatal("Ensure accepted a regular file")
	}
}

// The shared-/tmp attack: another account creates the directory first. Only
// root can hand a directory to someone else, so this runs only as root.
func TestEnsure_RefusesADirectoryOwnedByAnotherUser(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	dir := filepath.Join(t.TempDir(), "theirs")
	if err := os.Mkdir(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(dir); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("Ensure(another user's dir) = %v, want ErrUnsafe", err)
	}
}

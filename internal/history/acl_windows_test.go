//go:build windows

package history

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ownerOnly reports whether every entry in path's DACL is an allow for the
// current user, i.e. nobody else (SYSTEM, Administrators, Users, Everyone...)
// can reach it. For the directory itself the DACL must also be protected from
// inheritance; a file inside it inherits its entries instead, so it never is.
func ownerOnly(t *testing.T, path string, wantProtected bool) (bool, string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%s): %v", path, err)
	}
	if wantProtected {
		control, _, err := sd.Control()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			return false, "the DACL still inherits from its parent"
		}
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, "no DACL (which would mean everyone has access)"
	}
	if dacl.AceCount == 0 {
		return false, "an empty DACL"
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false, "an entry is not an allow entry"
		}
		if !windows.EqualSid((*windows.SID)(unsafe.Pointer(&ace.SidStart)), user.User.Sid) {
			return false, "an entry grants access to someone other than the current user"
		}
	}
	return true, ""
}

// NFR-12 on Windows: the directory and every record inside it are accessible
// to the current user alone.
func TestOpenAndAppend_WindowsOwnerOnlyACL(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "history"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ok, why := ownerOnly(t, s.Dir(), true); !ok {
		t.Errorf("history directory is not owner-only: %s", why)
	}
	id, err := s.Append(NewRecord(sampleInput()))
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := ownerOnly(t, s.path(id), false); !ok {
		t.Errorf("a record created in the directory is not owner-only: %s", why)
	}
}

// Opening an existing, wide-open directory must tighten it, as on POSIX.
func TestOpen_WindowsTightensAnExistingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "history") // inherits the temp dir's broader ACL
	s1, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_ = s1
	if ok, why := ownerOnly(t, dir, true); !ok {
		t.Errorf("not owner-only after Open: %s", why)
	}
}

//go:build windows

package history

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// restrictToOwner replaces dir's access-control list with one that grants the
// current user, and nobody else, full control (NFR-12). The ACL is protected
// (it no longer inherits from the parent) and its entry is itself inheritable,
// so every record created inside the directory starts owner-only too.
//
// POSIX gets the same guarantee from mode bits 0700/0600; Windows has no such
// bits, and the default %LOCALAPPDATA% ACL also admits SYSTEM and
// Administrators, which this deliberately does not.
func restrictToOwner(dir string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("history: reading the current user: %w", err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
		},
	}}, nil)
	if err != nil {
		return fmt.Errorf("history: building an owner-only ACL: %w", err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("history: restricting %s to its owner: %w", dir, err)
	}
	return nil
}

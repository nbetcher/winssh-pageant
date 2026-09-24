package security

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// GetUserSID Gets the SID of the current user.
func GetUserSID() (*windows.SID, error) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}

	return copyValidSID(user.User.Sid)
}

// GetHandleSID Gets SID for the given handle
func GetHandleSID(h windows.Handle) (*windows.SID, error) {
	securityDescriptor, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}

	sid, _, err := securityDescriptor.Owner()
	if err != nil {
		return nil, err
	}

	return copyValidSID(sid)
}

// GetDefaultSID Returns the default (Security Identifier) SID for the current user.
func GetDefaultSID() (*windows.SID, error) {
	proc := windows.CurrentProcess()
	return GetHandleSID(proc)
}

// Return an owned SID instead of retaining a pointer into a token or security
// descriptor buffer. Reject an absent owner rather than passing nil to EqualSid.
func copyValidSID(sid *windows.SID) (*windows.SID, error) {
	if sid == nil || !sid.IsValid() {
		return nil, fmt.Errorf("security descriptor has no valid SID")
	}
	return sid.Copy()
}

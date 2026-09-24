//go:build windows

package security

import (
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCurrentUserAndProcessOwner(t *testing.T) {
	user, err := GetUserSID()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := GetDefaultSID()
	if err != nil {
		t.Fatal(err)
	}
	userString, ownerString := user.String(), owner.String()
	runtime.GC()
	if !user.IsValid() || user.String() != userString || userString == "" {
		t.Fatal("current-user SID is invalid after collection")
	}
	if !owner.IsValid() || owner.String() != ownerString || ownerString == "" {
		t.Fatal("process-owner SID is invalid after collection")
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !windows.EqualSid(user, tokenUser.User.Sid) {
		t.Fatal("wrong current-user SID")
	}
}

func TestInvalidHandleAndAbsentOwner(t *testing.T) {
	if _, err := GetHandleSID(0); err == nil {
		t.Fatal("invalid kernel handle accepted")
	}
	if _, err := copyValidSID(nil); err == nil {
		t.Fatal("absent owner accepted")
	}
}

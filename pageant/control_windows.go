//go:build windows

package pageant

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/ndbeals/winssh-pageant/internal/security"
	"github.com/ndbeals/winssh-pageant/internal/win"
	"golang.org/x/sys/windows"
)

var coreWindowProcess = coreUser32.NewProc("GetWindowThreadProcessId")

func PrepareConsole() { _ = win.FixConsoleIfNeeded() }

// matchingProcess prevents an installer/portable copy from closing another
// installation or PuTTY's Pageant. The process handle also pins its identity.
func matchingProcess(hwnd win.HWND) (windows.Handle, error) {
	var pid uint32
	coreWindowProcess.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return 0, nil
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if err != nil {
		return 0, err
	}
	keep := false
	defer func() {
		if !keep {
			windows.CloseHandle(h)
		}
	}()
	var token windows.Token
	if err = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return 0, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return 0, err
	}
	ours, err := security.GetUserSID()
	if err != nil {
		return 0, err
	}
	if !windows.EqualSid(user.User.Sid, ours) {
		return 0, nil
	}
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err = windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return 0, err
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	// Paths on this installation are case-insensitive. Do not match basename.
	if !strings.EqualFold(filepath.Clean(exe), filepath.Clean(windows.UTF16ToString(buf[:size]))) {
		return 0, nil
	}
	keep = true
	return h, nil
}

// ExitRunning stops only the executable at this exact installation path in
// this interactive desktop, including a legacy version's Pageant window.
func ExitRunning() error {
	for _, class := range []string{controlClassName, wndClassName} {
		name, _ := windows.UTF16PtrFromString(class)
		hwnd := win.FindWindow(name, name)
		if hwnd == 0 {
			continue
		}
		h, err := matchingProcess(hwnd)
		if err != nil {
			return err
		}
		if h == 0 {
			continue
		}
		r, _, postErr := corePostMessage.Call(uintptr(hwnd), win.WM_CLOSE, 0, 0)
		if r == 0 {
			windows.CloseHandle(h)
			return fmt.Errorf("request exit: %w", postErr)
		}
		status, waitErr := windows.WaitForSingleObject(h, 10000)
		windows.CloseHandle(h)
		if waitErr != nil {
			return waitErr
		}
		if status != windows.WAIT_OBJECT_0 {
			return fmt.Errorf("agent did not exit within 10 seconds (status %d)", status)
		}
		return nil
	}
	return nil
}

func ShowRunningKeys() (bool, error) {
	name, _ := windows.UTF16PtrFromString(controlClassName)
	hwnd := win.FindWindow(name, name)
	if hwnd == 0 {
		return false, nil
	}
	h, err := matchingProcess(hwnd)
	if err != nil {
		return false, err
	}
	if h == 0 {
		return false, nil
	}
	defer windows.CloseHandle(h)
	r, _, err := corePostMessage.Call(uintptr(hwnd), showKeysMessage, 0, 0)
	if r == 0 {
		return false, err
	}
	return true, nil
}

func ShowError(err error) {
	body, _ := windows.UTF16PtrFromString(err.Error())
	title, _ := windows.UTF16PtrFromString("WinSSH-Pageant")
	coreUser32.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x10)
}

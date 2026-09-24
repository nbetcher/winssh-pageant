//go:build windows

package pageant

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"

	"github.com/ndbeals/winssh-pageant/internal/win"
	"github.com/ndbeals/winssh-pageant/openssh"
	"golang.org/x/sys/windows"
)

func TestDesktopNativeLayouts(t *testing.T) {
	// Exact SDK sizes matter: Shell_NotifyIcon rejects an incorrectly sized
	// record and common controls would otherwise read invalid pointers.
	wantNotify, wantItem, wantColumn := uintptr(976), uintptr(88), uintptr(56)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		wantNotify, wantItem, wantColumn = 956, 60, 44
	}
	for _, tc := range []struct {
		name      string
		got, want uintptr
	}{
		{"NOTIFYICONDATAW", unsafe.Sizeof(notifyIconData{}), wantNotify},
		{"LVITEMW", unsafe.Sizeof(uiListItem{}), wantItem},
		{"LVCOLUMNW", unsafe.Sizeof(uiListColumn{}), wantColumn},
	} {
		if tc.got != tc.want {
			t.Errorf("%s size = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestDesktopPeerTextCannotSpoofRowsOrDirections(t *testing.T) {
	got := cleanUIText("ssh\x00evil\r\nname\u202eexe\u2066key\u200b")
	if want := "ssh evil  name exe key "; got != want {
		t.Fatalf("cleanUIText = %q, want %q", got, want)
	}
	if got := cleanUIText(strings.Repeat("a", 4096)); len(got) != 2048 {
		t.Fatalf("unbounded UI text: %d bytes", len(got))
	}
}

func TestDesktopUTF16TruncationPreservesSurrogatePairs(t *testing.T) {
	var output [5]uint16
	copyUIText(output[:], "abc😀suffix")
	if got := string(utf16.Decode(output[:3])); got != "abc" || output[3] != 0 || output[4] != 0 {
		t.Fatalf("UTF-16 split at a surrogate pair: %#v", output)
	}
	copyUIText(output[:], "ab😀suffix")
	if got := string(utf16.Decode(output[:4])); got != "ab😀" || output[4] != 0 {
		t.Fatalf("UTF-16 pair lost: %#v", output)
	}
	copyUIText(output[:], "x")
	if output != [5]uint16{'x', 0, 0, 0, 0} {
		t.Fatalf("stale notification content retained: %#v", output)
	}
}

func TestDesktopNoticeFloodCannotBlockSigning(t *testing.T) {
	d := &desktop{notices: make(chan desktopNotice, 1)}
	d.notices <- desktopNotice{title: "first"}
	// A full queue takes the default branch and performs no HWND operation.
	d.notify("overflow", "peer data")
	if len(d.notices) != 1 || (<-d.notices).title != "first" {
		t.Fatal("full notice queue was not bounded")
	}
	d.closed.Store(true)
	d.notify("after close", "peer data")
	if len(d.notices) != 0 {
		t.Fatal("notification queued after shutdown")
	}
}

// Run explicitly in an interactive Windows session. This creates its own
// hidden host class and fixture key window; it never claims the Pageant class,
// connects to the user's agent, or starts a production pipe listener.
func TestDesktopNativeSmoke(t *testing.T) {
	if os.Getenv("WINSSH_DESKTOP_TEST") != "1" {
		t.Skip("set WINSSH_DESKTOP_TEST=1 for interactive native UI validation")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var d *desktop
	className := uiString(fmt.Sprintf("WinSSHPageantUITest-%d", os.Getpid()))
	callback := syscall.NewCallback(func(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
		if d != nil {
			if result, handled := d.onMessage(hwnd, msg, wParam, lParam); handled {
				return result
			}
		}
		return win.DefWindowProc(hwnd, msg, wParam, lParam)
	})
	class := win.WNDCLASSEX{
		CbSize: uint32(unsafe.Sizeof(win.WNDCLASSEX{})), LpfnWndProc: callback,
		HInstance: win.GetModuleHandle(nil), LpszClassName: className,
	}
	if win.RegisterClassEx(&class) == 0 {
		t.Fatalf("register isolated host: %v", win.GetLastError())
	}
	defer uiUnregisterClass.Call(uintptr(unsafe.Pointer(className)), uintptr(win.GetModuleHandle(nil)))
	host := win.CreateWindowEx(0, className, className, 0, 0, 0, 0, 0, 0, 0, win.GetModuleHandle(nil), nil)
	if host == 0 {
		t.Fatalf("create isolated host: %v", win.GetLastError())
	}
	defer uiDestroyWindow.Call(uintptr(host))
	var err error
	d, err = newDesktop(host, fmt.Sprintf(`\\.\pipe\winssh-pageant-unused-ui-test-%d`, os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if !d.trayAdded {
		t.Fatal("Explorer did not accept the isolated notification icon")
	}
	identifier := struct {
		Size   uint32
		Window win.HWND
		ID     uint32
		GUID   windows.GUID
	}{Window: host, ID: 1}
	identifier.Size = uint32(unsafe.Sizeof(identifier))
	iconRect := desktopShell32.NewProc("Shell_NotifyIconGetRect")
	var rect uiRect
	result, _, _ := iconRect.Call(uintptr(unsafe.Pointer(&identifier)), uintptr(unsafe.Pointer(&rect)))
	if int32(result) != 0 {
		t.Fatalf("registered tray icon is not discoverable: HRESULT %#x", result)
	}
	// Reproduce Explorer's loss of icon registration without restarting or
	// modifying the user's Explorer process.
	data := d.iconData()
	uiShellNotifyIcon.Call(2, uintptr(unsafe.Pointer(&data)))
	d.onMessage(host, d.taskbarReady, 0, 0)
	result, _, _ = iconRect.Call(uintptr(unsafe.Pointer(&identifier)), uintptr(unsafe.Pointer(&rect)))
	if int32(result) != 0 || !d.trayAdded {
		t.Fatal("tray icon was not restored after the taskbar recreation event")
	}
	d.showKeys()
	if d.keyWindow == 0 || d.keyList == 0 {
		t.Fatal("native key popup or list was not created")
	}
	windowText := desktopUser32.NewProc("GetWindowTextW")
	assertStatus := func(expected string) {
		t.Helper()
		var text [256]uint16
		windowText.Call(uintptr(d.keyStatus), uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)))
		if got := windows.UTF16ToString(text[:]); !strings.Contains(got, expected) {
			t.Fatalf("key status = %q; wanted %q", got, expected)
		}
	}
	d.displayKeys(desktopKeyResult{})
	assertStatus("No SSH keys are loaded")
	d.displayKeys(desktopKeyResult{err: fmt.Errorf("isolated fixture: unavailable")})
	assertStatus("OpenSSH agent unavailable")
	d.displayKeys(desktopKeyResult{keys: []openssh.Key{
		{Type: "ssh-ed25519", Fingerprint: "SHA256:fixture-for-native-ui-test", Comment: "Fixture key — no private material"},
		{Type: "ssh-rsa", Fingerprint: "SHA256:second-fixture", Comment: "Second fixture"},
	}})
	count, _, _ := uiSendMessage.Call(uintptr(d.keyList), 0x1004, 0, 0) // LVM_GETITEMCOUNT
	if count != 2 {
		t.Fatalf("native key list has %d rows, want 2", count)
	}
	var text [256]uint16
	item := uiListItem{SubItem: 1, Text: &text[0], TextMax: int32(len(text))}
	uiSendMessage.Call(uintptr(d.keyList), 0x1073, 0, uintptr(unsafe.Pointer(&item))) // LVM_GETITEMTEXTW
	if got := windows.UTF16ToString(text[:]); got != "SHA256:fixture-for-native-ui-test" {
		t.Fatalf("native fingerprint cell = %q", got)
	}
	uiSetWindowPos.Call(uintptr(d.keyWindow), 0, 0, 0, 680, 340, 0x16)
	var client uiRect
	uiGetClientRect.Call(uintptr(d.keyList), uintptr(unsafe.Pointer(&client)))
	if client.Right <= 0 || client.Bottom <= 0 {
		t.Fatalf("key list collapsed after resizing: %+v", client)
	}
	// Let the native controls process their queued paints, then validate that
	// Escape is handled through normal dialog keyboard navigation.
	peek := desktopUser32.NewProc("PeekMessageW")
	for i := 0; i < 100; i++ {
		var msg win.MSG
		got, _, _ := peek.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 1)
		if got == 0 {
			break
		}
		if !d.translateMessage(&msg) {
			win.TranslateMessage(&msg)
			win.DispatchMessage(&msg)
		}
	}
	keyMessage := win.MSG{HWnd: d.closeButton, Message: 0x100, WParam: 0x1b}
	if !d.translateMessage(&keyMessage) || d.keyWindow != 0 {
		t.Fatal("Escape did not close the native key popup")
	}
	d.close()
	result, _, _ = iconRect.Call(uintptr(unsafe.Pointer(&identifier)), uintptr(unsafe.Pointer(&rect)))
	if int32(result) == 0 {
		t.Fatal("tray icon remained registered after close")
	}
}

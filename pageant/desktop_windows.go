//go:build windows

package pageant

// This UI has a separate message loop from the synchronous Pageant transport.
// All HWND/GDI/Shell operations run on that loop's locked OS thread. Worker
// goroutines communicate only through bounded Go channels and PostMessage.

import (
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"syscall"
	"unicode"
	"unicode/utf16"
	"unsafe"

	"github.com/ndbeals/winssh-pageant/internal/win"
	"github.com/ndbeals/winssh-pageant/openssh"
	"golang.org/x/sys/windows"
)

const (
	wmTrayIcon      = 0x8000 + 51
	wmTrayNotice    = 0x8000 + 52
	wmKeysReady     = 0x8000 + 53
	trayRetryTimer  = 51
	menuShowKeys    = 1001
	menuToggleNotes = 1002
	menuExit        = 1003
	keyRefresh      = 1
	keyClose        = 2
)

var (
	desktopUser32           = windows.NewLazySystemDLL("user32.dll")
	desktopShell32          = windows.NewLazySystemDLL("shell32.dll")
	desktopGDI32            = windows.NewLazySystemDLL("gdi32.dll")
	desktopComctl32         = windows.NewLazySystemDLL("comctl32.dll")
	uiShellNotifyIcon       = desktopShell32.NewProc("Shell_NotifyIconW")
	uiExtractIconEx         = desktopShell32.NewProc("ExtractIconExW")
	uiRegisterWindowMessage = desktopUser32.NewProc("RegisterWindowMessageW")
	uiPostMessage           = desktopUser32.NewProc("PostMessageW")
	uiSendMessage           = desktopUser32.NewProc("SendMessageW")
	uiCreatePopupMenu       = desktopUser32.NewProc("CreatePopupMenu")
	uiAppendMenu            = desktopUser32.NewProc("AppendMenuW")
	uiTrackPopupMenu        = desktopUser32.NewProc("TrackPopupMenu")
	uiDestroyMenu           = desktopUser32.NewProc("DestroyMenu")
	uiSetForegroundWindow   = desktopUser32.NewProc("SetForegroundWindow")
	uiGetCursorPos          = desktopUser32.NewProc("GetCursorPos")
	uiSetTimer              = desktopUser32.NewProc("SetTimer")
	uiKillTimer             = desktopUser32.NewProc("KillTimer")
	uiDestroyIcon           = desktopUser32.NewProc("DestroyIcon")
	uiDestroyWindow         = desktopUser32.NewProc("DestroyWindow")
	uiShowWindow            = desktopUser32.NewProc("ShowWindow")
	uiSetWindowText         = desktopUser32.NewProc("SetWindowTextW")
	uiMoveWindow            = desktopUser32.NewProc("MoveWindow")
	uiGetClientRect         = desktopUser32.NewProc("GetClientRect")
	uiEnableWindow          = desktopUser32.NewProc("EnableWindow")
	uiIsDialogMessage       = desktopUser32.NewProc("IsDialogMessageW")
	uiSetFocus              = desktopUser32.NewProc("SetFocus")
	uiGetDpiForWindow       = desktopUser32.NewProc("GetDpiForWindow")
	uiSetWindowPos          = desktopUser32.NewProc("SetWindowPos")
	uiCreateFont            = desktopGDI32.NewProc("CreateFontW")
	uiDeleteObject          = desktopGDI32.NewProc("DeleteObject")
	uiInitCommonControls    = desktopComctl32.NewProc("InitCommonControlsEx")
	uiUnregisterClass       = desktopUser32.NewProc("UnregisterClassW")
	keysWindowClass         = uiString("WinSSHPageantKeys")
)

// notifyIconData matches NOTIFYICONDATAW, including pointer alignment on 386.
type notifyIconData struct {
	Size            uint32
	Window          win.HWND
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            win.HICON
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUID            windows.GUID
	BalloonIcon     win.HICON
}

type uiRect struct{ Left, Top, Right, Bottom int32 }

type uiMinMaxInfo struct {
	Reserved, MaxSize, MaxPosition, MinTrackSize, MaxTrackSize win.POINT
}

type uiListColumn struct {
	Mask                           uint32
	Format, Width                  int32
	Text                           *uint16
	TextMax, SubItem, Image, Order int32
	MinWidth, DefaultWidth, Ideal  int32
}

type uiListItem struct {
	Mask             uint32
	Item, SubItem    int32
	State, StateMask uint32
	Text             *uint16
	TextMax, Image   int32
	Param            uintptr
	Indent, GroupID  int32
	Columns          uint32
	ColumnIndices    *uint32
	ColumnFormats    *int32
	Group            int32
}

type desktopNotice struct{ title, body string }
type desktopKeyResult struct {
	keys []openssh.Key
	err  error
}

type desktop struct {
	hwnd          win.HWND // immutable; safe for worker PostMessage calls
	sshPipe       string
	closed        atomic.Bool
	notices       chan desktopNotice
	keysReady     chan desktopKeyResult
	icon          win.HICON
	largeIcon     win.HICON
	ownedIcon     win.HICON
	ownedLarge    win.HICON
	trayAdded     bool
	trayVersion4  bool
	taskbarReady  uint32
	notesEnabled  bool
	keyWindow     win.HWND
	keyList       win.HWND
	keyStatus     win.HWND
	refreshButton win.HWND
	closeButton   win.HWND
	font          uintptr
	dpi           uint32
	loadingKeys   bool
	keyClass      bool
}

func uiString(value string) *uint16 {
	// Text from a peer must never terminate a string early or spoof multiple
	// rows, bidi direction, or invisible key/application names in native UI.
	value = cleanUIText(value)
	ptr, _ := windows.UTF16PtrFromString(value)
	return ptr
}

func cleanUIText(value string) string {
	out := make([]rune, 0, min(len(value), 2048))
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = ' '
		}
		out = append(out, r)
		if len(out) == 2048 {
			break
		}
	}
	return string(out)
}

func copyUIText(destination []uint16, value string) {
	if len(destination) == 0 {
		return
	}
	clear(destination)
	encoded := utf16.Encode([]rune(cleanUIText(value)))
	limit := len(destination) - 1
	if len(encoded) > limit {
		encoded = encoded[:limit]
		if limit > 0 && encoded[limit-1] >= 0xd800 && encoded[limit-1] <= 0xdbff {
			encoded = encoded[:limit-1]
		}
	}
	copy(destination, encoded)
}

func newDesktop(hwnd win.HWND, sshPipe string) (*desktop, error) {
	d := &desktop{
		hwnd: hwnd, sshPipe: sshPipe, notesEnabled: true, dpi: 96,
		notices: make(chan desktopNotice, 16), keysReady: make(chan desktopKeyResult, 1),
	}
	// Load the same icon resource used by Explorer and the installer. Both
	// ExtractIconEx results are private handles, unlike the stock fallback.
	if path, err := os.Executable(); err == nil {
		pathPtr, convErr := windows.UTF16PtrFromString(path)
		if convErr == nil {
			uiExtractIconEx.Call(uintptr(unsafe.Pointer(pathPtr)), 0,
				uintptr(unsafe.Pointer(&d.largeIcon)), uintptr(unsafe.Pointer(&d.icon)), 1)
			d.ownedIcon, d.ownedLarge = d.icon, d.largeIcon
		}
	}
	if d.icon == 0 {
		d.icon = win.LoadIcon(0, win.MAKEINTRESOURCE(win.IDI_APPLICATION))
	}
	if d.largeIcon == 0 {
		d.largeIcon = d.icon
	}
	ready, _, err := uiRegisterWindowMessage.Call(uintptr(unsafe.Pointer(uiString("TaskbarCreated"))))
	if ready == 0 {
		d.close()
		return nil, fmt.Errorf("register taskbar restart message: %w", err)
	}
	d.taskbarReady = uint32(ready)
	d.addTrayIcon()
	return d, nil
}

func (d *desktop) iconData() notifyIconData {
	return notifyIconData{Size: uint32(unsafe.Sizeof(notifyIconData{})), Window: d.hwnd, ID: 1}
}

func (d *desktop) addTrayIcon() {
	if d.closed.Load() || d.trayAdded {
		return
	}
	data := d.iconData()
	data.Flags = 1 | 2 | 4 | 0x80 // MESSAGE | ICON | TIP | SHOWTIP
	data.Icon, data.CallbackMessage = d.icon, wmTrayIcon
	copyUIText(data.Tip[:], "winssh-pageant — running")
	ok, _, _ := uiShellNotifyIcon.Call(0, uintptr(unsafe.Pointer(&data))) // NIM_ADD
	if ok == 0 {
		// Explorer can be unavailable briefly during logon or a restart.
		uiSetTimer.Call(uintptr(d.hwnd), trayRetryTimer, 5000, 0)
		return
	}
	d.trayAdded = true
	uiKillTimer.Call(uintptr(d.hwnd), trayRetryTimer)
	data.Version = 4
	ok, _, _ = uiShellNotifyIcon.Call(4, uintptr(unsafe.Pointer(&data)))
	d.trayVersion4 = ok != 0
}

// notify is safe for transport workers and never waits for the UI or Explorer.
func (d *desktop) notify(title, body string) {
	if d == nil || d.closed.Load() {
		return
	}
	notice := desktopNotice{cleanUIText(title), cleanUIText(body)}
	select {
	case d.notices <- notice:
		uiPostMessage.Call(uintptr(d.hwnd), wmTrayNotice, 0, 0)
	default:
		// Signing must continue under notification floods or a busy desktop.
	}
}

func (d *desktop) onMessage(hwnd win.HWND, msg uint32, wParam, lParam uintptr) (uintptr, bool) {
	if hwnd != d.hwnd {
		return 0, false
	}
	if msg == d.taskbarReady {
		d.trayAdded = false
		d.addTrayIcon()
		return 0, true
	}
	switch msg {
	case wmTrayIcon:
		event := uint32(lParam)
		if d.trayVersion4 {
			event &= 0xffff
		}
		switch event {
		case 0x7b, 0x205: // WM_CONTEXTMENU, legacy WM_RBUTTONUP
			d.showTrayMenu(wParam)
		case 0x400, 0x401, 0x203: // NIN_SELECT, NIN_KEYSELECT, legacy double click
			d.showKeys()
		}
		return 0, true
	case wmTrayNotice:
		select {
		case notice := <-d.notices:
			if d.notesEnabled && d.trayAdded {
				data := d.iconData()
				data.Flags = 0x10 | 0x40         // INFO | REALTIME: discard stale queued notices
				data.InfoFlags = 1 | 0x10 | 0x80 // INFO | NOSOUND | RESPECT_QUIET_TIME
				copyUIText(data.InfoTitle[:], notice.title)
				copyUIText(data.Info[:], notice.body)
				uiShellNotifyIcon.Call(1, uintptr(unsafe.Pointer(&data)))
			}
		default:
		}
		return 0, true
	case wmKeysReady:
		select {
		case result := <-d.keysReady:
			d.loadingKeys = false
			if d.keyWindow != 0 {
				d.displayKeys(result)
			}
		default:
		}
		return 0, true
	case 0x113: // WM_TIMER
		if wParam == trayRetryTimer {
			d.addTrayIcon()
			return 0, true
		}
	}
	return 0, false
}

func (d *desktop) showTrayMenu(anchor uintptr) {
	menu, _, _ := uiCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer uiDestroyMenu.Call(menu)
	uiAppendMenu.Call(menu, 0, menuShowKeys, uintptr(unsafe.Pointer(uiString("Show SSH &keys…"))))
	check := uintptr(0)
	if d.notesEnabled {
		check = 8 // MF_CHECKED
	}
	uiAppendMenu.Call(menu, check, menuToggleNotes, uintptr(unsafe.Pointer(uiString("Signing &notifications"))))
	uiAppendMenu.Call(menu, 0x800, 0, 0) // MF_SEPARATOR
	uiAppendMenu.Call(menu, 0, menuExit, uintptr(unsafe.Pointer(uiString("E&xit"))))
	var point win.POINT
	if d.trayVersion4 && anchor != ^uintptr(0) {
		point.X, point.Y = int32(int16(anchor&0xffff)), int32(int16((anchor>>16)&0xffff))
	}
	if !d.trayVersion4 || (point.X == -1 && point.Y == -1) {
		uiGetCursorPos.Call(uintptr(unsafe.Pointer(&point)))
	}
	uiSetForegroundWindow.Call(uintptr(d.hwnd))
	selected, _, _ := uiTrackPopupMenu.Call(menu, 0x100|0x2, uintptr(point.X), uintptr(point.Y), 0, uintptr(d.hwnd), 0)
	// Required for dismissal on click-away when the owner is a hidden window.
	uiPostMessage.Call(uintptr(d.hwnd), 0, 0, 0)
	switch selected {
	case menuShowKeys:
		d.showKeys()
		return
	case menuToggleNotes:
		d.notesEnabled = !d.notesEnabled
	case menuExit:
		uiPostMessage.Call(uintptr(d.hwnd), win.WM_CLOSE, 0, 0)
		return
	}
	data := d.iconData()
	uiShellNotifyIcon.Call(3, uintptr(unsafe.Pointer(&data))) // NIM_SETFOCUS
}

func (d *desktop) showKeys() {
	if d.keyWindow != 0 {
		uiShowWindow.Call(uintptr(d.keyWindow), 9) // SW_RESTORE
		uiSetForegroundWindow.Call(uintptr(d.keyWindow))
		return
	}
	if !d.keyClass {
		controls := struct{ Size, Classes uint32 }{8, 1} // ICC_LISTVIEW_CLASSES
		ok, _, err := uiInitCommonControls.Call(uintptr(unsafe.Pointer(&controls)))
		if ok == 0 {
			log.Printf("Initialize key-list controls: %v", err)
			return
		}
		class := win.WNDCLASSEX{
			CbSize: uint32(unsafe.Sizeof(win.WNDCLASSEX{})), LpfnWndProc: syscall.NewCallback(d.keysWndProc),
			HInstance: win.GetModuleHandle(nil), HIcon: d.largeIcon, HIconSm: d.icon,
			HCursor:       win.LoadCursor(0, win.MAKEINTRESOURCE(32512)),
			HbrBackground: win.GetSysColorBrush(15), LpszClassName: keysWindowClass,
		}
		if win.RegisterClassEx(&class) == 0 {
			log.Printf("Register key window: %v", win.GetLastError())
			return
		}
		d.keyClass = true
	}
	d.keyWindow = win.CreateWindowEx(0x00010000, keysWindowClass, uiString("SSH keys — winssh-pageant"),
		0x00cf0000, -2147483648, -2147483648, 940, 420, 0, 0, win.GetModuleHandle(nil), nil)
	if d.keyWindow == 0 {
		log.Printf("Create key window: %v", win.GetLastError())
		return
	}
	d.dpi = d.windowDPI()
	if d.dpi != 96 {
		// Window dimensions are physical pixels under PerMonitorV2. Preserve
		// the intended logical size on the monitor where the popup opens.
		uiSetWindowPos.Call(uintptr(d.keyWindow), 0, 0, 0,
			uintptr(d.scale(940)), uintptr(d.scale(420)), 0x16)
	}
	d.keyStatus = d.control("STATIC", "Loading SSH keys…", 0, 0)
	d.keyList = d.control("SysListView32", "SSH keys", 0x00800000|0x00010000|1|4|8, 100)
	d.refreshButton = d.control("BUTTON", "&Refresh", 0x00010000|1, keyRefresh)
	d.closeButton = d.control("BUTTON", "&Close", 0x00010000, keyClose)
	if d.keyStatus == 0 || d.keyList == 0 || d.refreshButton == 0 || d.closeButton == 0 {
		log.Printf("Create key-list controls: %v", win.GetLastError())
		uiDestroyWindow.Call(uintptr(d.keyWindow))
		return
	}
	uiSendMessage.Call(uintptr(d.keyList), 0x1036, 0, 0x20|0x10000) // extended list styles
	for index, column := range []struct {
		title string
		width int32
	}{
		{"Type", 140}, {"SHA256 fingerprint", 380}, {"Comment", 330},
	} {
		definition := uiListColumn{Mask: 1 | 2 | 4 | 8, Width: d.scale(column.width), Text: uiString(column.title), SubItem: int32(index)}
		uiSendMessage.Call(uintptr(d.keyList), 0x1061, uintptr(index), uintptr(unsafe.Pointer(&definition)))
	}
	d.updateFont()
	d.layoutKeys()
	uiShowWindow.Call(uintptr(d.keyWindow), 5)
	uiSetForegroundWindow.Call(uintptr(d.keyWindow))
	uiSetFocus.Call(uintptr(d.refreshButton))
	d.refreshKeys()
}

func (d *desktop) control(class, text string, style uint32, id uintptr) win.HWND {
	return win.CreateWindowEx(0, uiString(class), uiString(text), style|0x50000000,
		0, 0, 0, 0, d.keyWindow, win.HMENU(id), win.GetModuleHandle(nil), nil)
}

func (d *desktop) windowDPI() uint32 {
	if uiGetDpiForWindow.Find() == nil {
		dpi, _, _ := uiGetDpiForWindow.Call(uintptr(d.keyWindow))
		if dpi > 0 {
			return uint32(dpi)
		}
	}
	return 96
}

func (d *desktop) scale(value int32) int32 { return value * int32(d.dpi) / 96 }

func (d *desktop) updateFont() {
	font, _, _ := uiCreateFont.Call(uintptr(-d.scale(12)), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 5, 0,
		uintptr(unsafe.Pointer(uiString("Segoe UI"))))
	if font == 0 {
		return
	}
	previous := d.font
	d.font = font
	for _, hwnd := range []win.HWND{d.keyStatus, d.keyList, d.refreshButton, d.closeButton} {
		uiSendMessage.Call(uintptr(hwnd), 0x30, font, 1) // WM_SETFONT
	}
	if previous != 0 {
		uiDeleteObject.Call(previous)
	}
}

func (d *desktop) layoutKeys() {
	if d.keyList == 0 {
		return
	}
	var rect uiRect
	uiGetClientRect.Call(uintptr(d.keyWindow), uintptr(unsafe.Pointer(&rect)))
	pad, status, button, gap := d.scale(12), d.scale(32), d.scale(28), d.scale(8)
	width, height := rect.Right-rect.Left, rect.Bottom-rect.Top
	move := func(hwnd win.HWND, x, y, w, h int32) {
		uiMoveWindow.Call(uintptr(hwnd), uintptr(x), uintptr(y), uintptr(max(w, 1)), uintptr(max(h, 1)), 1)
	}
	move(d.keyStatus, pad, pad, width-2*pad, status)
	move(d.keyList, pad, pad+status+gap, width-2*pad, height-3*pad-status-gap-button)
	move(d.refreshButton, width-pad-d.scale(184), height-pad-button, d.scale(88), button)
	move(d.closeButton, width-pad-d.scale(88), height-pad-button, d.scale(88), button)
}

func (d *desktop) keysWndProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case 0x5: // WM_SIZE
		d.layoutKeys()
		return 0
	case 0x24: // WM_GETMINMAXINFO
		info := (*uiMinMaxInfo)(unsafe.Pointer(lParam))
		info.MinTrackSize = win.POINT{X: d.scale(560), Y: d.scale(280)}
		return 0
	case 0x2e0: // WM_DPICHANGED
		d.dpi = uint32(wParam & 0xffff)
		d.updateFont()
		rect := (*uiRect)(unsafe.Pointer(lParam))
		uiSetWindowPos.Call(uintptr(hwnd), 0, uintptr(rect.Left), uintptr(rect.Top),
			uintptr(rect.Right-rect.Left), uintptr(rect.Bottom-rect.Top), 0x14)
		d.layoutKeys()
		return 0
	case 0x111: // WM_COMMAND
		switch uint16(wParam) {
		case keyRefresh:
			d.refreshKeys()
		case keyClose:
			uiDestroyWindow.Call(uintptr(hwnd))
		}
		return 0
	case win.WM_CLOSE:
		uiDestroyWindow.Call(uintptr(hwnd))
		return 0
	case 0x82: // WM_NCDESTROY: child controls no longer reference the font
		d.keyWindow, d.keyList, d.keyStatus, d.refreshButton, d.closeButton = 0, 0, 0, 0, 0
		if d.font != 0 {
			uiDeleteObject.Call(d.font)
			d.font = 0
		}
	}
	return win.DefWindowProc(hwnd, msg, wParam, lParam)
}

func (d *desktop) translateMessage(msg *win.MSG) bool {
	if d.keyWindow == 0 {
		return false
	}
	handled, _, _ := uiIsDialogMessage.Call(uintptr(d.keyWindow), uintptr(unsafe.Pointer(msg)))
	return handled != 0
}

func (d *desktop) refreshKeys() {
	if d.loadingKeys {
		uiEnableWindow.Call(uintptr(d.refreshButton), 0)
		return
	}
	d.loadingKeys = true
	uiSetWindowText.Call(uintptr(d.keyStatus), uintptr(unsafe.Pointer(uiString("Loading SSH keys from the OpenSSH agent…"))))
	uiEnableWindow.Call(uintptr(d.refreshButton), 0)
	uiSendMessage.Call(uintptr(d.keyList), 0x1009, 0, 0) // LVM_DELETEALLITEMS: no stale keys
	go func() {
		keys, err := openssh.ListKeys(d.sshPipe)
		if d.closed.Load() {
			return
		}
		select {
		case d.keysReady <- desktopKeyResult{keys: keys, err: err}:
			uiPostMessage.Call(uintptr(d.hwnd), wmKeysReady, 0, 0)
		default:
		}
	}()
}

func (d *desktop) displayKeys(result desktopKeyResult) {
	uiEnableWindow.Call(uintptr(d.refreshButton), 1)
	uiSendMessage.Call(uintptr(d.keyList), 0x1009, 0, 0)
	status := fmt.Sprintf("%d SSH key(s) available. Only public key details are shown.", len(result.keys))
	if result.err != nil {
		status = "OpenSSH agent unavailable. Check the agent service, then select Refresh."
		log.Printf("List SSH keys: %v", result.err)
	} else if len(result.keys) == 0 {
		status = "No SSH keys are loaded. Add a key with ssh-add, then select Refresh."
	}
	uiSetWindowText.Call(uintptr(d.keyStatus), uintptr(unsafe.Pointer(uiString(status))))
	if result.err != nil {
		return
	}
	uiSendMessage.Call(uintptr(d.keyList), 0xb, 0, 0) // WM_SETREDRAW
	for index, key := range result.keys {
		item := uiListItem{Mask: 1, Item: int32(index), Text: uiString(key.Type)}
		uiSendMessage.Call(uintptr(d.keyList), 0x104d, 0, uintptr(unsafe.Pointer(&item)))
		for subitem, value := range []string{key.Fingerprint, key.Comment} {
			item.SubItem, item.Text = int32(subitem+1), uiString(value)
			uiSendMessage.Call(uintptr(d.keyList), 0x1074, uintptr(index), uintptr(unsafe.Pointer(&item)))
		}
	}
	uiSendMessage.Call(uintptr(d.keyList), 0xb, 1, 0)
	// MoveWindow's repaint flag also invalidates the list after bulk updates.
	d.layoutKeys()
}

func (d *desktop) close() {
	if d == nil || d.closed.Swap(true) {
		return
	}
	uiKillTimer.Call(uintptr(d.hwnd), trayRetryTimer)
	if d.trayAdded {
		data := d.iconData()
		uiShellNotifyIcon.Call(2, uintptr(unsafe.Pointer(&data)))
		d.trayAdded = false
	}
	if d.keyWindow != 0 {
		uiDestroyWindow.Call(uintptr(d.keyWindow))
	}
	if d.keyClass {
		uiUnregisterClass.Call(uintptr(unsafe.Pointer(keysWindowClass)), uintptr(win.GetModuleHandle(nil)))
	}
	if d.ownedIcon != 0 {
		uiDestroyIcon.Call(uintptr(d.ownedIcon))
	}
	if d.ownedLarge != 0 && d.ownedLarge != d.ownedIcon {
		uiDestroyIcon.Call(uintptr(d.ownedLarge))
	}
}

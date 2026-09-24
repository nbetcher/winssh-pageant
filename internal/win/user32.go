package win

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

var (
	libuser32        = windows.NewLazySystemDLL("user32.dll")
	loadCursor       = libuser32.NewProc("LoadCursorW")
	loadIcon         = libuser32.NewProc("LoadIconW")
	getSysColorBrush = libuser32.NewProc("GetSysColorBrush")
	registerClassEx  = libuser32.NewProc("RegisterClassExW")
	createWindowEx   = libuser32.NewProc("CreateWindowExW")
	defWindowProc    = libuser32.NewProc("DefWindowProcW")
	getMessage       = libuser32.NewProc("GetMessageW")
	translateMessage = libuser32.NewProc("TranslateMessage")
	dispatchMessage  = libuser32.NewProc("DispatchMessageW")
	postQuitMessage  = libuser32.NewProc("PostQuitMessage")
	findWindow       = libuser32.NewProc("FindWindowW")
)

func MAKEINTRESOURCE(id uintptr) *uint16 { return (*uint16)(unsafe.Pointer(id)) }
func LoadCursor(instance HINSTANCE, name *uint16) HCURSOR {
	r, _, _ := loadCursor.Call(uintptr(instance), uintptr(unsafe.Pointer(name)))
	return HCURSOR(r)
}
func LoadIcon(instance HINSTANCE, name *uint16) HICON {
	r, _, _ := loadIcon.Call(uintptr(instance), uintptr(unsafe.Pointer(name)))
	return HICON(r)
}
func GetSysColorBrush(index int) HBRUSH {
	r, _, _ := getSysColorBrush.Call(uintptr(index))
	return HBRUSH(r)
}
func RegisterClassEx(class *WNDCLASSEX) ATOM {
	r, _, _ := registerClassEx.Call(uintptr(unsafe.Pointer(class)))
	return ATOM(r)
}

//revive:disable:line-length-limit,argument-limit
func CreateWindowEx(exStyle uint32, class, title *uint16, style uint32, x, y, width, height int32, parent HWND, menu HMENU, instance HINSTANCE, param unsafe.Pointer) HWND {
	r, _, _ := createWindowEx.Call(uintptr(exStyle), uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)), uintptr(style), uintptr(x), uintptr(y), uintptr(width), uintptr(height), uintptr(parent), uintptr(menu), uintptr(instance), uintptr(param))
	return HWND(r)
}
func DefWindowProc(hwnd HWND, msg uint32, wp, lp uintptr) uintptr {
	r, _, _ := defWindowProc.Call(uintptr(hwnd), uintptr(msg), wp, lp)
	return r
}

// LazyProc.Call has Go's uintptrescapes annotation. Native calls can invoke Go
// callbacks and grow the goroutine stack; pointers retained across those calls
// must escape to stable storage. Direct SyscallN does not provide that contract.
func GetMessage(msg *MSG, hwnd HWND, filterMin, filterMax uint32) BOOL {
	r, _, _ := getMessage.Call(uintptr(unsafe.Pointer(msg)), uintptr(hwnd), uintptr(filterMin), uintptr(filterMax))
	return BOOL(r)
}
func TranslateMessage(msg *MSG) bool {
	r, _, _ := translateMessage.Call(uintptr(unsafe.Pointer(msg)))
	return r != 0
}
func DispatchMessage(msg *MSG) uintptr {
	r, _, _ := dispatchMessage.Call(uintptr(unsafe.Pointer(msg)))
	return r
}
func PostQuitMessage(code int32) { postQuitMessage.Call(uintptr(code)) }
func FindWindow(class, title *uint16) HWND {
	r, _, _ := findWindow.Call(uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(title)))
	return HWND(r)
}

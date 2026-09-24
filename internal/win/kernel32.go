package win

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

var (
	libkernel32     = windows.NewLazySystemDLL("kernel32.dll")
	getLastError    = libkernel32.NewProc("GetLastError")
	getModuleHandle = libkernel32.NewProc("GetModuleHandleW")
	attachConsole   = libkernel32.NewProc("AttachConsole")
)

func GetLastError() uint32 { r, _, _ := getLastError.Call(); return uint32(r) }
func GetModuleHandle(name *uint16) HINSTANCE {
	r, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(name)))
	return HINSTANCE(r)
}

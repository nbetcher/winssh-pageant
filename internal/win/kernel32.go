package win

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// Library
	libkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	// Functions
	getLastError    = libkernel32.NewProc("GetLastError")
	getModuleHandle = libkernel32.NewProc("GetModuleHandleW")
	attachConsole   = libkernel32.NewProc("AttachConsole")
)

func GetLastError() uint32 {
	ret, _, _ := syscall.Syscall(getLastError.Addr(), 0,
		0,
		0,
		0)

	return uint32(ret)
}

func GetModuleHandle(lpModuleName *uint16) HINSTANCE {
	ret, _, _ := syscall.Syscall(getModuleHandle.Addr(), 1,
		uintptr(unsafe.Pointer(lpModuleName)),
		0,
		0)

	return HINSTANCE(ret)
}

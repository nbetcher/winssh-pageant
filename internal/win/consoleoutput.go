package win

import (
	"errors"
	"golang.org/x/sys/windows"
	"log"
	"os"
	"sync"
)

var consoleOnce sync.Once
var consoleError error

// Keep Go's original wrappers alive: their finalizers must not close handles
// that AttachConsole installs for the parent console.
var originalOutput, originalError *os.File

func AttachConsole() error {
	r, _, err := attachConsole.Call(ATTACH_PARENT_PROCESS)
	if r != 0 || errors.Is(err, windows.ERROR_INVALID_HANDLE) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil
	}
	return err
}

func FixConsoleIfNeeded() error {
	consoleOnce.Do(func() {
		originalOutput, originalError = os.Stdout, os.Stderr
		stdout, _ := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
		stderr, _ := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
		valid := func(h windows.Handle) bool { return h != 0 && h != windows.InvalidHandle }
		if !valid(stdout) && !valid(stderr) {
			consoleError = AttachConsole()
		}
		// Preserve redirected output supplied by a shell/installer.
		if !valid(stdout) {
			if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil && valid(h) {
				os.Stdout = os.NewFile(uintptr(h), "stdout")
			}
		}
		if !valid(stderr) {
			if h, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE); err == nil && valid(h) {
				os.Stderr = os.NewFile(uintptr(h), "stderr")
			}
		}
		log.SetOutput(os.Stderr)
	})
	return consoleError
}

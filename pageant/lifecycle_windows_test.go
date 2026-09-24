//go:build windows

package pageant

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/ndbeals/winssh-pageant/internal/win"
	"golang.org/x/sys/windows"
)

// A subprocess is needed because ExitRunning waits for process termination.
// The helper owns no Pageant window or pipe and never accesses a real key.
func TestDesktopLifecycleHelperProcess(t *testing.T) {
	if os.Getenv("WINSSH_DESKTOP_HELPER") != "1" {
		t.Skip("only runs as the isolated lifecycle-test subprocess")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var d *desktop
	hwnd, cleanup, err := createWindow(controlClassName, func(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
		if d != nil {
			if result, handled := d.onMessage(hwnd, msg, wp, lp); handled {
				return result
			}
		}
		return lifecycleWndProc(hwnd, msg, wp, lp)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	d, err = newDesktop(hwnd, `\\.\pipe\winssh-pageant-unused-lifecycle-fixture`)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	if !d.trayAdded {
		t.Fatal("isolated subprocess tray icon was not registered")
	}
	fmt.Printf("DESKTOP_READY %d\n", hwnd)
	var msg win.MSG
	for {
		result := win.GetMessage(&msg, 0, 0, 0)
		if result == -1 {
			t.Fatal("isolated subprocess message loop failed")
		}
		if result == 0 {
			break
		}
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)
	}
	d.close()
	if d.trayAdded || !d.closed.Load() {
		t.Fatal("desktop did not clean up after graceful exit")
	}
	fmt.Println("DESKTOP_CLOSED")
}

func TestDesktopExitRunningSubprocess(t *testing.T) {
	if os.Getenv("WINSSH_DESKTOP_TEST") != "1" {
		t.Skip("set WINSSH_DESKTOP_TEST=1 for isolated interactive lifecycle validation")
	}
	class := uiString(controlClassName)
	if win.FindWindow(class, class) != 0 {
		t.Skip("a real application control window exists; preserving it")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestDesktopLifecycleHelperProcess$", "-test.v")
	command.Env = append(os.Environ(), "WINSSH_DESKTOP_HELPER=1")
	command.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	// Every cleanup action here is scoped to the subprocess created above.
	defer command.Process.Kill()
	ready := make(chan win.HWND, 1)
	readDone := make(chan bool, 1)
	waitDone := make(chan error, 1)
	go func() {
		closed := false
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "DESKTOP_READY ") {
				value, err := strconv.ParseUint(strings.TrimPrefix(line, "DESKTOP_READY "), 10, 64)
				if err == nil {
					ready <- win.HWND(value)
				}
			}
			if line == "DESKTOP_CLOSED" {
				closed = true
			}
		}
		readDone <- closed && scanner.Err() == nil
		// Drain StdoutPipe before Wait closes it, preserving the final cleanup
		// marker even when the subprocess exits immediately after writing it.
		waitDone <- command.Wait()
	}()
	var hwnd win.HWND
	select {
	case hwnd = <-ready:
	case err := <-waitDone:
		t.Fatalf("helper exited before readiness: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("isolated helper did not become ready")
	}
	handle, err := matchingProcess(hwnd)
	if err != nil || handle == 0 {
		t.Fatalf("helper did not match exact executable and user: %v", err)
	}
	pid, err := windows.GetProcessId(handle)
	windows.CloseHandle(handle)
	if err != nil || pid != uint32(command.Process.Pid) {
		t.Fatalf("matched process %d is not the created helper: %v", pid, err)
	}
	if err := ExitRunning(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("graceful helper exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ExitRunning returned before helper exited")
	}
	if !<-readDone {
		t.Fatal("helper did not confirm native desktop cleanup")
	}
	identifier := struct {
		Size   uint32
		Window win.HWND
		ID     uint32
		GUID   windows.GUID
	}{Window: hwnd, ID: 1}
	identifier.Size = uint32(unsafe.Sizeof(identifier))
	var rect uiRect
	result, _, _ := desktopShell32.NewProc("Shell_NotifyIconGetRect").Call(uintptr(unsafe.Pointer(&identifier)), uintptr(unsafe.Pointer(&rect)))
	if int32(result) == 0 {
		t.Fatal("subprocess tray icon survived graceful application exit")
	}
}

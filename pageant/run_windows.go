//go:build windows

package pageant

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/user"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/ndbeals/winssh-pageant/internal/security"
	"github.com/ndbeals/winssh-pageant/internal/win"
	"github.com/ndbeals/winssh-pageant/openssh"
	"golang.org/x/sys/windows"
)

const (
	agentPipeName    = `\\.\pipe\pageant.%s.%s`
	agentCopyDataID  = 0x804e50ba
	wndClassName     = "Pageant"
	controlClassName = "WinSSHPageantBridge"
	showKeysMessage  = 0x8000 + 73
	maxClients       = 32
	clientTimeout    = 2 * time.Minute
)

var (
	crypt32                = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectMemory = crypt32.NewProc("CryptProtectMemory")
	coreKernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procOpenFileMappingA   = coreKernel32.NewProc("OpenFileMappingA")
	coreUser32             = windows.NewLazySystemDLL("user32.dll")
	coreDestroyWindow      = coreUser32.NewProc("DestroyWindow")
	corePostMessage        = coreUser32.NewProc("PostMessageW")
	coreUnregisterClass    = coreUser32.NewProc("UnregisterClassW")
	wndClassNamePtr, _     = windows.UTF16PtrFromString(wndClassName)
)

type runtimeState struct {
	desktop   *desktop
	listener  net.Listener
	mu        sync.Mutex
	clients   map[net.Conn]struct{}
	upstreams map[*openssh.Session]struct{}
	closing   bool
}

func defaultHandlerFunc(p *Pageant, request []byte) ([]byte, error) {
	return openssh.QueryAgent(p.SSHAgentPipe, request)
}

// Run owns the UI thread. Synchronous legacy IPC has a separate thread so
// hardware-key prompts and unavailable upstreams cannot freeze the tray.
func (p *Pageant) Run() error {
	if p.PageantRequestHandler == nil {
		p.PageantRequestHandler = defaultHandlerFunc
	}
	if p.SSHAgentPipe == "" {
		p.SSHAgentPipe = DefaultSSHAgentPipe
	}
	if err := win.FixConsoleIfNeeded(); err != nil {
		log.Printf("console: %v", err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sid, err := security.GetUserSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + sid.String() + ")")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	mutexName, _ := windows.UTF16PtrFromString(`Local\WinSSHPageantBridge-` + sid.String())
	mutex, err := windows.CreateMutex(&sa, false, mutexName)
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if p.ShowKeysOnStart {
			var shown bool
			shown, err = ShowRunningKeys()
			if !shown && err == nil {
				return errors.New("another WinSSH-Pageant installation is running; open its key window from the tray")
			}
			return err
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("single instance: %w", err)
	}
	if doesPageantWindowExist() {
		return errors.New("another Pageant agent is already running; exit it before starting WinSSH-Pageant")
	}
	p.state = &runtimeState{clients: make(map[net.Conn]struct{})}
	if p.pageantPipe {
		p.state.listener, err = newPageantListener()
		if err != nil {
			return fmt.Errorf("create Pageant pipe: %w", err)
		}
	}
	defer p.closeConnections()
	hwnd, cleanup, err := createWindow(controlClassName, p.wndProc)
	if err != nil {
		return err
	}
	defer cleanup()
	d, err := newDesktop(hwnd, p.SSHAgentPipe)
	if err != nil {
		return err
	}
	p.state.desktop = d
	defer d.close()
	ready := make(chan error, 1)
	stopIPC := make(chan struct{})
	go p.runIPCWindow(ready, stopIPC)
	if err = <-ready; err != nil {
		close(stopIPC)
		return err
	}
	defer close(stopIPC)
	if p.state.listener != nil {
		go p.pipeProxy()
	}
	if p.ShowKeysOnStart {
		d.showKeys()
	}
	var msg win.MSG
	for {
		r := win.GetMessage(&msg, 0, 0, 0)
		if r == -1 {
			return fmt.Errorf("GetMessage: %d", win.GetLastError())
		}
		if r == 0 {
			return nil
		}
		if d.translateMessage(&msg) {
			continue
		}
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)
	}
}

func createWindow(class string, proc func(win.HWND, uint32, uintptr, uintptr) uintptr) (win.HWND, func(), error) {
	name, _ := windows.UTF16PtrFromString(class)
	inst := win.GetModuleHandle(nil)
	wc := win.WNDCLASSEX{CbSize: uint32(unsafe.Sizeof(win.WNDCLASSEX{})), HInstance: inst,
		LpfnWndProc: syscall.NewCallback(proc), LpszClassName: name}
	if win.RegisterClassEx(&wc) == 0 {
		return 0, nil, fmt.Errorf("register %s: %d", class, win.GetLastError())
	}
	cleanupClass := func() { coreUnregisterClass.Call(uintptr(unsafe.Pointer(name)), uintptr(inst)) }
	hwnd := win.CreateWindowEx(win.WS_EX_TOOLWINDOW, name, name, 0, 0, 0, 0, 0, 0, 0, inst, nil)
	if hwnd == 0 {
		cleanupClass()
		return 0, nil, fmt.Errorf("create %s: %d", class, win.GetLastError())
	}
	return hwnd, func() { coreDestroyWindow.Call(uintptr(hwnd)); cleanupClass() }, nil
}

func (p *Pageant) runIPCWindow(ready chan<- error, stop <-chan struct{}) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	hwnd, cleanup, err := createWindow(wndClassName, p.ipcWndProc)
	ready <- err
	if err != nil {
		return
	}
	defer cleanup()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-stop:
			corePostMessage.Call(uintptr(hwnd), win.WM_CLOSE, 0, 0)
		case <-done:
		}
	}()
	var msg win.MSG
	for win.GetMessage(&msg, 0, 0, 0) > 0 {
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)
	}
}

func (p *Pageant) wndProc(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
	if p.state != nil && p.state.desktop != nil {
		if msg == showKeysMessage {
			p.state.desktop.showKeys()
			return 0
		}
		if r, ok := p.state.desktop.onMessage(hwnd, msg, wp, lp); ok {
			return r
		}
	}
	return lifecycleWndProc(hwnd, msg, wp, lp)
}

func (p *Pageant) ipcWndProc(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
	if msg == win.WM_COPYDATA {
		return p.handleCopyData(lp)
	}
	return lifecycleWndProc(hwnd, msg, wp, lp)
}

func lifecycleWndProc(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
	switch msg {
	case win.WM_QUERYENDSESSION:
		return 1
	case 0x16:
		if wp != 0 {
			win.PostQuitMessage(0)
		}
		return 0
	case win.WM_CLOSE:
		coreDestroyWindow.Call(uintptr(hwnd))
		return 0
	case win.WM_DESTROY:
		win.PostQuitMessage(0)
		return 0
	}
	return win.DefWindowProc(hwnd, msg, wp, lp)
}

func doesPageantWindowExist() bool { return win.FindWindow(wndClassNamePtr, wndClassNamePtr) != 0 }

type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

// Windows marshals COPYDATASTRUCT and cbData bytes while SendMessage is active.
// Validate the bounded NUL-terminated name before passing it to an ANSI API.
func copyDataName(cd *copyDataStruct) ([]byte, bool) {
	if cd.dwData != agentCopyDataID || cd.lpData == 0 || cd.cbData < 2 || cd.cbData > 260 {
		return nil, false
	}
	name := unsafe.Slice((*byte)(unsafe.Pointer(cd.lpData)), int(cd.cbData))
	if name[len(name)-1] != 0 || bytes.IndexByte(name[:len(name)-1], 0) >= 0 {
		return nil, false
	}
	return append([]byte(nil), name...), true
}

func openFileMap(access, inherit uint32, name uintptr) (windows.Handle, error) {
	h, _, err := procOpenFileMappingA.Call(uintptr(access), uintptr(inherit), name)
	if h == 0 {
		return 0, err
	}
	return windows.Handle(h), nil
}

func (p *Pageant) handleCopyData(lp uintptr) uintptr {
	if lp == 0 {
		return 0
	}
	name, ok := copyDataName((*copyDataStruct)(unsafe.Pointer(lp)))
	if !ok {
		return 0
	}
	h, err := openFileMap(windows.FILE_MAP_WRITE|windows.READ_CONTROL, 0, uintptr(unsafe.Pointer(&name[0])))
	runtime.KeepAlive(name)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	userSID, err := security.GetUserSID()
	if err != nil {
		return 0
	}
	owner, err := security.GetHandleSID(h)
	if err != nil || !windows.EqualSid(owner, userSID) {
		return 0
	}
	view, err := windows.MapViewOfFile(h, windows.FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		return 0
	}
	defer windows.UnmapViewOfFile(view)
	var info windows.MemoryBasicInformation
	if windows.VirtualQuery(view, &info, unsafe.Sizeof(info)) != nil || info.RegionSize < 5 {
		return 0
	}
	// Legacy Pageant has a 16383-byte mapping. Do not use page-rounded lengths
	// to exceed the protocol's shared-buffer capacity.
	n := info.RegionSize
	if n > openssh.AgentMaxMessageLength {
		n = openssh.AgentMaxMessageLength
	}
	mapped := unsafe.Slice((*byte)(unsafe.Pointer(view)), n)
	length := binary.BigEndian.Uint32(mapped[:4])
	if length < 1 || uintptr(length) > n-4 {
		return 0
	}
	request := append([]byte(nil), mapped[:int(length)+4]...)
	result := p.query(request, clientFromMapping(string(name[:len(name)-1])))
	if len(result) > len(mapped) {
		result = agentFailure()
	}
	copy(mapped, result)
	return 1
}

func agentFailure() []byte { return []byte{0, 0, 0, 1, 5} }

func (p *Pageant) query(request []byte, client clientInfo) []byte {
	return p.queryUsing(request, client, func(frame []byte) ([]byte, error) {
		return p.PageantRequestHandler(p, frame)
	})
}

func (p *Pageant) queryUsing(request []byte, client clientInfo, handler func([]byte) ([]byte, error)) []byte {
	if openssh.ValidateRequest(request) != nil {
		return agentFailure()
	}
	result, err := handler(request)
	if err != nil || openssh.ValidateResponse(result) != nil {
		result = agentFailure()
	}
	if p.state != nil && p.state.desktop != nil {
		p.notifySigning(request, result, client)
	}
	return result
}

func capiObfuscateString(realname string) (string, error) {
	data := make([]byte, ((len(realname)+1+15)/16)*16)
	copy(data, realname)
	r, _, err := procCryptProtectMemory.Call(uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 1)
	if r == 0 {
		return "", fmt.Errorf("CryptProtectMemory: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func newPageantListener() (net.Listener, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	parts := strings.Split(u.Username, `\`)
	hash, err := capiObfuscateString(wndClassName)
	if err != nil {
		return nil, err
	}
	return listenUserPipe(fmt.Sprintf(agentPipeName, parts[len(parts)-1], hash))
}

func listenUserPipe(name string) (net.Listener, error) {
	sid, err := security.GetUserSID()
	if err != nil {
		return nil, err
	}
	// go-winio additionally rejects remote clients and reserves the first instance.
	return winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + sid.String() + ")", InputBufferSize: 16384, OutputBufferSize: 16384})
}

func (p *Pageant) closeConnections() {
	if p.state == nil {
		return
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	p.state.closing = true
	if p.state.listener != nil {
		_ = p.state.listener.Close()
	}
	for c := range p.state.clients {
		_ = c.Close()
	}
	for upstream := range p.state.upstreams {
		_ = upstream.Close()
	}
}

func (p *Pageant) pipeProxy() {
	for {
		c, err := p.state.listener.Accept()
		if err != nil {
			return
		}
		p.state.mu.Lock()
		if p.state.closing || len(p.state.clients) >= maxClients {
			p.state.mu.Unlock()
			_ = c.Close()
			continue
		}
		p.state.clients[c] = struct{}{}
		p.state.mu.Unlock()
		go func() {
			defer func() { p.state.mu.Lock(); delete(p.state.clients, c); p.state.mu.Unlock() }()
			p.pipeListen(c)
		}()
	}
}

func (p *Pageant) pipeListen(c net.Conn) {
	defer c.Close()
	client := clientFromPipe(c)
	handler := func(frame []byte) ([]byte, error) { return p.PageantRequestHandler(p, frame) }
	// Honor public custom handlers, while keeping the built-in upstream session
	// alive for this client (required by connection-bound OpenSSH extensions).
	if p.PageantRequestHandler == nil || reflect.ValueOf(p.PageantRequestHandler).Pointer() == reflect.ValueOf(defaultHandlerFunc).Pointer() {
		upstream := openssh.NewSession(p.SSHAgentPipe)
		defer upstream.Close()
		if p.state != nil {
			p.state.mu.Lock()
			if p.state.closing {
				p.state.mu.Unlock()
				return
			}
			if p.state.upstreams == nil {
				p.state.upstreams = make(map[*openssh.Session]struct{})
			}
			p.state.upstreams[upstream] = struct{}{}
			p.state.mu.Unlock()
			defer func() { p.state.mu.Lock(); delete(p.state.upstreams, upstream); p.state.mu.Unlock() }()
		}
		handler = upstream.Query
	}
	for {
		// Forwarded agent channels may legitimately be idle for hours. Bound
		// incomplete frames after their first byte, not the idle connection.
		if c.SetReadDeadline(time.Time{}) != nil {
			return
		}
		var prefix [4]byte
		if _, err := io.ReadFull(c, prefix[:1]); err != nil {
			return
		}
		if c.SetReadDeadline(time.Now().Add(clientTimeout)) != nil {
			return
		}
		if _, err := io.ReadFull(c, prefix[1:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(prefix[:])
		if n < 1 || n > openssh.AgentMaxMessageLength-4 {
			return
		}
		request := make([]byte, int(n)+4)
		copy(request, prefix[:])
		if _, err := io.ReadFull(c, request[4:]); err != nil {
			return
		}
		result := p.queryUsing(request, client, handler)
		if c.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
			return
		}
		for len(result) > 0 {
			n, err := c.Write(result)
			if err != nil || n == 0 {
				return
			}
			result = result[n:]
		}
	}
}

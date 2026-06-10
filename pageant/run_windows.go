//go:build windows

package pageant

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"encoding/binary"
	"encoding/hex"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/ndbeals/winssh-pageant/internal/security"
	"github.com/ndbeals/winssh-pageant/internal/win"
	"github.com/ndbeals/winssh-pageant/openssh"
)

func defaultHandlerFunc(p *Pageant, request []byte) ([]byte, error) {
	return openssh.QueryAgent(p.SSHAgentPipe, request)
}

func (p *Pageant) Run() {
	// A nil handler (e.g. New(..., nil), WithPageantRequestHandler(nil), or a
	// bare &Pageant{}) would be called as a nil func from the window procedure
	// and the pipe goroutines; fall back to the default rather than crash.
	if p.PageantRequestHandler == nil {
		p.PageantRequestHandler = defaultHandlerFunc
	}

	err := win.FixConsoleIfNeeded()
	if err != nil {
		log.Printf("FixConsoleOutput: %v\n", err)
	}

	// Check if any application claiming to be a Pageant Window is already running
	if doesPageantWindowExist() {
		log.Println("This application is already running, exiting.")
		return
	}

	// Start a proxy/redirector for the pageant named pipes
	if p.pageantPipe {
		go p.pipeProxy()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pageantWindow := p.createPageantWindow()
	if pageantWindow == 0 {
		log.Println(fmt.Errorf("createPageantWindow failed: %v", win.GetLastError()))
		return
	}

	// main message loop
	var msg win.MSG
	for win.GetMessage(&msg, pageantWindow, 0, 0) > 0 {
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)
	}
}

const (
	// windows consts
	//revive:disable:var-naming,exported
	CRYPTPROTECTMEMORY_BLOCK_SIZE    = 16
	CRYPTPROTECTMEMORY_CROSS_PROCESS = 1
	FILE_MAP_ALL_ACCESS              = 0xf001f
	FILE_MAP_WRITE                   = 0x2

	// Pageant consts
	agentPipeName   = `\\.\pipe\pageant.%s.%s`
	agentCopyDataID = 0x804e50ba
	wndClassName    = "Pageant"
)

var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectMemory = crypt32.NewProc("CryptProtectMemory")

	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	procOpenFileMappingA = modkernel32.NewProc("OpenFileMappingA")
	wndClassNamePtr, _   = syscall.UTF16PtrFromString(wndClassName)
)

// copyDataStruct is used to pass data in the WM_COPYDATA message.
// We directly pass a pointer to our copyDataStruct type, be careful that it matches the Windows type exactly
type copyDataStruct struct {
	dwData uintptr
	cbData uint32
	lpData uintptr
}

func openFileMap(dwDesiredAccess, bInheritHandle uint32, mapNamePtr uintptr) (windows.Handle, error) {
	mapPtr, _, err := procOpenFileMappingA.Call(uintptr(dwDesiredAccess), uintptr(bInheritHandle), mapNamePtr)

	//Properly compare syscall.Errno to number, instead of naive (i18n-unaware) string comparison
	if err.(syscall.Errno) == windows.ERROR_SUCCESS {
		err = nil
	}
	return windows.Handle(mapPtr), err
}

func doesPageantWindowExist() bool {
	return win.FindWindow(wndClassNamePtr, nil) != 0
}

func (p *Pageant) registerPageantWindow(hInstance win.HINSTANCE) (atom win.ATOM) {
	var wc win.WNDCLASSEX
	wc.Style = 0

	wc.CbSize = uint32(unsafe.Sizeof(wc))
	wc.LpfnWndProc = syscall.NewCallback(p.wndProc)
	wc.CbClsExtra = 0
	wc.CbWndExtra = 0
	wc.HInstance = hInstance
	wc.HIcon = win.LoadIcon(0, win.MAKEINTRESOURCE(win.IDI_APPLICATION))
	wc.HCursor = win.LoadCursor(0, win.MAKEINTRESOURCE(win.IDC_IBEAM))
	wc.HbrBackground = win.GetSysColorBrush(win.BLACK_BRUSH)
	wc.LpszMenuName = nil
	wc.LpszClassName = wndClassNamePtr
	wc.HIconSm = win.LoadIcon(0, win.MAKEINTRESOURCE(win.IDI_APPLICATION))

	return win.RegisterClassEx(&wc)
}

func (p *Pageant) createPageantWindow() win.HWND {
	inst := win.GetModuleHandle(nil)
	atom := p.registerPageantWindow(inst)
	if atom == 0 {
		log.Println(fmt.Errorf("RegisterClass failed: %d", win.GetLastError()))
		return 0
	}

	// CreateWindowEx
	pageantWindow := win.CreateWindowEx(
		win.WS_EX_APPWINDOW,
		wndClassNamePtr,
		wndClassNamePtr,
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		inst,
		nil,
	)

	return pageantWindow
}

func (p *Pageant) wndProc(hWnd win.HWND, message uint32, wParam uintptr, lParam uintptr) uintptr {
	switch message {
	case win.WM_COPYDATA:
		return p.handleCopyData(lParam)
	case win.WM_DESTROY, win.WM_CLOSE, win.WM_QUIT, win.WM_QUERYENDSESSION:
		// Handle system shutdowns and process sigterms etc
		win.PostQuitMessage(0)
		return 0
	}

	return win.DefWindowProc(hWnd, message, wParam, lParam)
}

// handleCopyData services a Pageant WM_COPYDATA request: it validates the
// sender, maps the client-supplied shared memory, forwards the request to the
// handler, and writes the reply back into the same buffer.
func (p *Pageant) handleCopyData(lParam uintptr) uintptr {
	copyData := (*copyDataStruct)(unsafe.Pointer(lParam))
	if copyData.dwData != agentCopyDataID {
		return 0
	}

	fileMap, err := openFileMap(FILE_MAP_ALL_ACCESS, 0, copyData.lpData)
	if err != nil {
		log.Println(err)
		return 0
	}
	defer windows.CloseHandle(fileMap)

	// check security
	ourself, err := security.GetUserSID()
	if err != nil {
		log.Println(err)
		return 0
	}
	ourself2, err := security.GetDefaultSID()
	if err != nil {
		log.Println(err)
		return 0
	}
	mapOwner, err := security.GetHandleSID(fileMap)
	if err != nil {
		log.Println(err)
		return 0
	}
	if !windows.EqualSid(mapOwner, ourself) && !windows.EqualSid(mapOwner, ourself2) {
		return 0
	}

	// Passed security checks, copy data
	sharedMemory, err := windows.MapViewOfFile(fileMap, FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		log.Println(err)
		return 0
	}
	defer windows.UnmapViewOfFile(sharedMemory)

	// The requesting client controls the size of the mapped region, which may be
	// smaller than AgentMaxMessageLength. Query the actual size so we never read
	// from or write past the mapped view.
	var memInfo windows.MemoryBasicInformation
	if err := windows.VirtualQuery(sharedMemory, &memInfo, unsafe.Sizeof(memInfo)); err != nil {
		log.Println(err)
		return 0
	}
	mappedLen := memInfo.RegionSize
	if mappedLen > openssh.AgentMaxResponseLength {
		mappedLen = openssh.AgentMaxResponseLength
	}
	if mappedLen < 4 {
		return 0
	}
	sharedMemoryArray := unsafe.Slice((*byte)(unsafe.Pointer(sharedMemory)), mappedLen)

	// msgLen is the client-declared request length. Validate it against the
	// mapped size BEFORE adding the 4-byte prefix, so the addition cannot wrap
	// (uint32, and uintptr is 32-bit on the 386 build). mappedLen >= 4 here.
	msgLen := binary.BigEndian.Uint32(sharedMemoryArray[:4])
	if uintptr(msgLen) > mappedLen-4 {
		return 0
	}
	size := msgLen + 4 // +4 for the size uint itself

	// Query the windows OpenSSH agent via the windows named pipe
	result, err := p.PageantRequestHandler(p, sharedMemoryArray[:size])
	if err != nil {
		log.Printf("Error in PageantRequestHandler: %+v\n", err)
		return 0
	}
	// The reply is written back into the client's buffer. Fail rather than return
	// an empty reply (which would leave the client's own request in shared
	// memory) or one that does not fit the mapping.
	if len(result) == 0 || uintptr(len(result)) > mappedLen {
		return 0
	}
	copy(sharedMemoryArray, result)

	return 1
}

func capiObfuscateString(realname string) string {
	cryptlen := len(realname) + 1
	cryptlen += CRYPTPROTECTMEMORY_BLOCK_SIZE - 1
	cryptlen /= CRYPTPROTECTMEMORY_BLOCK_SIZE
	cryptlen *= CRYPTPROTECTMEMORY_BLOCK_SIZE

	cryptdata := make([]byte, cryptlen)
	copy(cryptdata, realname)

	pDataIn := uintptr(unsafe.Pointer(&cryptdata[0]))
	cbDataIn := uintptr(cryptlen)
	dwFlags := uintptr(CRYPTPROTECTMEMORY_CROSS_PROCESS)

	//revive:disable:unhandled-error  - pageant ignores errors
	procCryptProtectMemory.Call(pDataIn, cbDataIn, dwFlags)

	hash := sha256.Sum256(cryptdata)
	return hex.EncodeToString(hash[:])
}

func (p *Pageant) pipeProxy() {
	currentUser, err := user.Current()
	if err != nil {
		log.Println(err)
		return
	}

	// Username is typically "DOMAIN\user" or "MACHINE\user"; fall back to the
	// whole string when there is no domain/host prefix (otherwise indexing the
	// split result would panic).
	nameParts := strings.Split(currentUser.Username, `\`)
	namePart := nameParts[len(nameParts)-1]
	pipeName := fmt.Sprintf(agentPipeName, namePart, capiObfuscateString(wndClassName))
	listener, err := winio.ListenPipe(pipeName, nil)
	if err != nil {
		log.Println(err)
	} else {
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Println(err)
				return
			}
			go p.pipeListen(conn)
		}
	}
}

func (p *Pageant) pipeListen(pageantConn net.Conn) {
	defer pageantConn.Close()
	reader := bufio.NewReader(pageantConn)

	for {
		lenBuf := make([]byte, 4)
		_, err := io.ReadFull(reader, lenBuf)
		if err != nil {
			return
		}

		bufferLen := binary.BigEndian.Uint32(lenBuf)
		// Reject oversized requests before allocating; bufferLen is read from
		// the client and would otherwise allow an unbounded (up to ~4 GiB)
		// allocation per message.
		if bufferLen > openssh.AgentMaxMessageLength {
			log.Printf("Pipe: request length %d exceeds maximum %d\n", bufferLen, openssh.AgentMaxMessageLength)
			return
		}
		readBuf := make([]byte, bufferLen)
		_, err = io.ReadFull(reader, readBuf)
		if err != nil {
			return
		}

		result, err := p.PageantRequestHandler(p, append(lenBuf, readBuf...))
		if err != nil {
			log.Printf("Pipe: Error in PageantRequestHandler: %+v\n", err)
			return
		}
		if len(result) == 0 {
			log.Println("Pipe: empty result from PageantRequestHandler")
			return
		}

		_, err = pageantConn.Write(result)
		if err != nil {
			return
		}
	}
}

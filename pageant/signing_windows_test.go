//go:build windows

package pageant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/ndbeals/winssh-pageant/internal/security"
	"github.com/ndbeals/winssh-pageant/internal/win"
	"golang.org/x/sys/windows"
)

func signingString(value []byte) []byte {
	result := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(result, uint32(len(value)))
	copy(result[4:], value)
	return result
}

func signingFrame(payload []byte) []byte { return signingString(payload) }

func signingReadFrame(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > 4096 {
		return nil, fmt.Errorf("unexpected fixture frame length %d", size)
	}
	frame := make([]byte, 4+int(size))
	copy(frame, header[:])
	_, err := io.ReadFull(conn, frame[4:])
	return frame, err
}

func signingTakeString(data *[]byte) ([]byte, error) {
	if len(*data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	size := binary.BigEndian.Uint32((*data)[:4])
	if uint64(size) > uint64(len(*data)-4) {
		return nil, io.ErrUnexpectedEOF
	}
	value := (*data)[4 : 4+int(size)]
	*data = (*data)[4+int(size):]
	return value, nil
}

// This fixture owns a fresh, in-memory key and two private test pipes. No
// installed agent or user's key is ever queried. Signature verification proves
// that both bridge transports preserve the complete SSH signing transaction.
func TestSigningAcrossRealPipeAndWindowTransports(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyBlob := append(signingString([]byte("ssh-ed25519")), signingString(publicKey)...)
	prefix := fmt.Sprintf("winssh-signing-fixture-%d-%d", os.Getpid(), time.Now().UnixNano())
	upstreamName := `\\.\pipe\` + prefix + "-upstream"
	upstream, err := listenUserPipe(upstreamName)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	agentDone := make(chan error, 1)
	go func() {
		for range 2 {
			conn, err := upstream.Accept()
			if err != nil {
				agentDone <- err
				return
			}
			err = func() error {
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return err
				}
				request, err := signingReadFrame(conn)
				if err != nil {
					return err
				}
				if request[4] != 13 {
					return fmt.Errorf("expected agent sign request, got %d", request[4])
				}
				// SSH2_AGENTC_SIGN_REQUEST is message 13, not the request-
				// identities message. All key/data/flag bytes must survive.
				remaining := request[5:]
				key, err := signingTakeString(&remaining)
				if err != nil {
					return err
				}
				if !bytes.Equal(key, keyBlob) {
					return fmt.Errorf("bridge changed the public key blob")
				}
				data, err := signingTakeString(&remaining)
				if err != nil {
					return err
				}
				if len(remaining) != 4 || binary.BigEndian.Uint32(remaining) != 0 {
					return fmt.Errorf("bridge changed signing flags")
				}
				signature := ed25519.Sign(privateKey, data)
				blob := append(signingString([]byte("ssh-ed25519")), signingString(signature)...)
				reply := signingFrame(append([]byte{14}, signingString(blob)...))
				for _, b := range reply { // exercise fragmented upstream response reads
					if _, err := conn.Write([]byte{b}); err != nil {
						return err
					}
				}
				return nil
			}()
			if err != nil {
				agentDone <- err
				return
			}
		}
		agentDone <- nil
	}()
	p := NewDefaultHandler(upstreamName, false)
	bridgeName := `\\.\pipe\` + prefix + "-bridge"
	bridge, err := listenUserPipe(bridgeName)
	if err != nil {
		t.Fatal(err)
	}
	p.state = &runtimeState{listener: bridge, clients: make(map[net.Conn]struct{})}
	defer p.closeConnections()
	go p.pipeProxy()
	requestFor := func(data []byte) []byte {
		payload := append([]byte{13}, signingString(keyBlob)...)
		payload = append(payload, signingString(data)...)
		payload = append(payload, 0, 0, 0, 0)
		return signingFrame(payload)
	}
	verify := func(reply, original []byte) {
		t.Helper()
		if len(reply) < 5 || int(binary.BigEndian.Uint32(reply)) != len(reply)-4 || reply[4] != 14 {
			t.Fatalf("bridge did not return a framed signature: %v", reply)
		}
		remaining := reply[5:]
		blob, err := signingTakeString(&remaining)
		if err != nil || len(remaining) != 0 {
			t.Fatalf("invalid signature envelope: %v", err)
		}
		algorithm, err := signingTakeString(&blob)
		if err != nil || string(algorithm) != "ssh-ed25519" {
			t.Fatalf("invalid signature algorithm: %v", err)
		}
		signature, err := signingTakeString(&blob)
		if err != nil || len(blob) != 0 {
			t.Fatalf("invalid signature value: %v", err)
		}
		if !ed25519.Verify(publicKey, original, signature) {
			t.Fatal("signature does not authenticate the original request data")
		}
	}
	pipeData := []byte("SSH authentication fixture through actual Windows named pipes\x00with binary data\xff")
	client, err := winio.DialPipe(bridgeName, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = client.Write(requestFor(pipeData)); err != nil {
		t.Fatal(err)
	}
	reply, err := signingReadFrame(client)
	if err != nil {
		t.Fatal(err)
	}
	verify(reply, pipeData)
	client.Close()

	// Use a unique test window class, not Pageant's well-known class, so a
	// running developer desktop agent is never displaced or contacted.
	windowReady := make(chan win.HWND, 1)
	windowDone := make(chan struct{})
	windowErr := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(windowDone)
		hwnd, cleanup, err := createWindow(prefix+"-window", p.ipcWndProc)
		if err != nil {
			windowErr <- err
			windowReady <- 0
			return
		}
		defer cleanup()
		windowReady <- hwnd
		var msg win.MSG
		for win.GetMessage(&msg, 0, 0, 0) > 0 {
			win.TranslateMessage(&msg)
			win.DispatchMessage(&msg)
		}
	}()
	hwnd := <-windowReady
	if hwnd == 0 {
		t.Fatal(<-windowErr)
	}
	defer func() {
		posted, _, postErr := corePostMessage.Call(uintptr(hwnd), win.WM_CLOSE, 0, 0)
		if posted == 0 {
			t.Errorf("post IPC close: %v", postErr)
		}
		select {
		case <-windowDone:
		case <-time.After(5 * time.Second):
			t.Error("isolated IPC window did not stop")
		}
	}()
	sid, err := security.GetUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid.String() + "D:P(A;;GA;;;" + sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	mapName := prefix + "-mapping"
	namePtr, _ := windows.UTF16PtrFromString(mapName)
	mapping, err := windows.CreateFileMapping(windows.InvalidHandle, &sa, windows.PAGE_READWRITE, 0, 16383, namePtr)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(mapping)
	view, err := windows.MapViewOfFile(mapping, windows.FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.UnmapViewOfFile(view)
	mapped := unsafe.Slice((*byte)(unsafe.Pointer(view)), 16383)
	windowData := []byte("Distinct SSH authentication fixture through native WM_COPYDATA\x00\xfe")
	copy(mapped, requestFor(windowData))
	// Cross-process WM_COPYDATA provides Windows-owned memory to the receiver.
	// Our same-process fixture must reproduce that ownership explicitly: a Go
	// allocation converted into LPARAM would lose checkptr provenance when the
	// native callback converts it back to a pointer.
	ansiName := testNativeBuffer(t, len(mapName)+1)
	copy(ansiName, mapName)
	ansiName[len(mapName)] = 0
	copyDataStorage := testNativeBuffer(t, int(unsafe.Sizeof(copyDataStruct{})))
	copyData := (*copyDataStruct)(unsafe.Pointer(&copyDataStorage[0]))
	*copyData = copyDataStruct{dwData: agentCopyDataID, cbData: uint32(len(ansiName)), lpData: uintptr(unsafe.Pointer(&ansiName[0]))}
	var messageResult uintptr
	sent, _, sendErr := coreUser32.NewProc("SendMessageTimeoutW").Call(uintptr(hwnd), win.WM_COPYDATA, 0,
		uintptr(unsafe.Pointer(copyData)), 2, 5000, uintptr(unsafe.Pointer(&messageResult)))
	if sent == 0 || messageResult != 1 {
		t.Fatalf("native WM_COPYDATA signing failed: %d, %d, %v", sent, messageResult, sendErr)
	}
	responseSize := int(binary.BigEndian.Uint32(mapped)) + 4
	if responseSize < 5 || responseSize > len(mapped) {
		t.Fatalf("invalid mapped response length %d", responseSize)
	}
	verify(mapped[:responseSize], windowData)
	select {
	case err := <-agentDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fixture agent did not complete both signing requests")
	}
}

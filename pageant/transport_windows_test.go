//go:build windows

package pageant

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/ndbeals/winssh-pageant/internal/security"
	"golang.org/x/sys/windows"
)

func TestPipeFramesAndFailures(t *testing.T) {
	for _, tt := range []struct {
		name  string
		reply []byte
		err   error
		want  []byte
	}{
		{"success", []byte{0, 0, 0, 5, 12, 0, 0, 0, 0}, nil, []byte{0, 0, 0, 5, 12, 0, 0, 0, 0}},
		{"handler error", nil, errors.New("upstream offline"), agentFailure()},
		{"malformed reply", []byte{0, 0, 0, 99, 12}, nil, agentFailure()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			p := New("", false, func(_ *Pageant, request []byte) ([]byte, error) {
				if !bytes.Equal(request, []byte{0, 0, 0, 1, 11}) {
					t.Errorf("bad request %v", request)
				}
				return tt.reply, tt.err
			})
			done := make(chan struct{})
			go func() { p.pipeListen(server); close(done) }()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			// More than one request per connection, fragmented at every byte.
			for range 2 {
				for _, b := range []byte{0, 0, 0, 1, 11} {
					if _, err := client.Write([]byte{b}); err != nil {
						t.Fatal(err)
					}
				}
				got := make([]byte, len(tt.want))
				if _, err := io.ReadFull(client, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, tt.want) {
					t.Fatalf("reply %v want %v", got, tt.want)
				}
			}
			client.Close()
			<-done
		})
	}
}

func TestPipeRejectsInvalidLengths(t *testing.T) {
	for _, length := range []uint32{0, 16380, 0xffffffff} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			p := New("", false, func(_ *Pageant, _ []byte) ([]byte, error) {
				t.Error("invalid request reached handler")
				return agentFailure(), nil
			})
			go p.pipeListen(server)
			client.SetDeadline(time.Now().Add(time.Second))
			var prefix [4]byte
			binary.BigEndian.PutUint32(prefix[:], length)
			client.Write(prefix[:])
			var b [1]byte
			if _, err := client.Read(b[:]); !errors.Is(err, io.EOF) {
				t.Fatalf("want closed connection, got %v", err)
			}
		})
	}
}

// Callback fixtures must have native allocation provenance, as real Windows
// COPYDATASTRUCT buffers do. A Go pointer hidden in uintptr is intentionally
// rejected by checkptr and would not model the actual callback boundary.
func testNativeBuffer(t *testing.T, size int) []byte {
	t.Helper()
	if size <= 0 || uint64(size) > uint64(^uint32(0)) {
		t.Fatal("invalid native fixture size")
	}
	ptr, err := windows.LocalAlloc(windows.LPTR, uint32(size))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := windows.LocalFree(windows.Handle(ptr)); err != nil {
			t.Errorf("free native fixture: %v", err)
		}
	})
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), size)
}

func TestCopyDataNameBounds(t *testing.T) {
	for _, tt := range []struct {
		name   []byte
		length uint32
		valid  bool
	}{
		{[]byte{'x', 0}, 2, true}, {[]byte{'x', 0, 'y', 0}, 4, false}, {[]byte{'x', 'y'}, 2, false},
		{[]byte{'x', 0}, 0, false}, {[]byte{'x', 0}, 261, false},
	} {
		name := testNativeBuffer(t, len(tt.name))
		copy(name, tt.name)
		cd := (*copyDataStruct)(unsafe.Pointer(&testNativeBuffer(t, int(unsafe.Sizeof(copyDataStruct{})))[0]))
		*cd = copyDataStruct{dwData: agentCopyDataID, cbData: tt.length, lpData: uintptr(unsafe.Pointer(&name[0]))}
		_, ok := copyDataName(cd)
		if ok != tt.valid {
			t.Errorf("length %d: got %v", tt.length, ok)
		}
	}
	if _, ok := copyDataName(&copyDataStruct{dwData: agentCopyDataID, cbData: 2}); ok {
		t.Error("accepted nil pointer")
	}
}

func TestCopyDataRealMapping(t *testing.T) {
	name := fmt.Sprintf("WinSSHPageantTest-%d", os.Getpid())
	user, err := security.GetUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + user.String() + "D:P(A;;GA;;;" + user.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	ptr, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateFileMapping(windows.InvalidHandle, &sa, windows.PAGE_READWRITE, 0, 16383, ptr)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	view, err := windows.MapViewOfFile(h, windows.FILE_MAP_WRITE, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.UnmapViewOfFile(view)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(view)), 16383)
	nameBytes := testNativeBuffer(t, len(name)+1)
	copy(nameBytes, name)
	cd := (*copyDataStruct)(unsafe.Pointer(&testNativeBuffer(t, int(unsafe.Sizeof(copyDataStruct{})))[0]))
	*cd = copyDataStruct{dwData: agentCopyDataID, cbData: uint32(len(nameBytes)), lpData: uintptr(unsafe.Pointer(&nameBytes[0]))}
	p := New("", false, func(_ *Pageant, request []byte) ([]byte, error) {
		if !bytes.Equal(request, []byte{0, 0, 0, 1, 11}) {
			t.Errorf("request %v", request)
		}
		return []byte{0, 0, 0, 5, 12, 0, 0, 0, 0}, nil
	})
	copy(buf, []byte{0, 0, 0, 1, 11})
	if p.handleCopyData(uintptr(unsafe.Pointer(cd))) != 1 || !bytes.Equal(buf[:9], []byte{0, 0, 0, 5, 12, 0, 0, 0, 0}) {
		t.Fatal("shared-memory exchange failed")
	}
	copy(buf, []byte{255, 255, 255, 255})
	if p.handleCopyData(uintptr(unsafe.Pointer(cd))) != 0 {
		t.Fatal("accepted overflow")
	}
}

func TestUserOnlyPipeAndShutdown(t *testing.T) {
	name := fmt.Sprintf(`\\.\pipe\winssh-pageant-test-%d`, os.Getpid())
	l, err := listenUserPipe(name)
	if err != nil {
		t.Fatal(err)
	}
	p := New("", false, func(_ *Pageant, _ []byte) ([]byte, error) { return agentFailure(), nil })
	p.state = &runtimeState{listener: l, clients: make(map[net.Conn]struct{})}
	defer p.closeConnections()
	go p.pipeProxy()
	c, err := winio.DialPipe(name, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fd := c.(interface{ Fd() uintptr }).Fd()
	sd, err := windows.GetSecurityInfo(windows.Handle(fd), windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := security.GetUserSID()
	if err != nil {
		t.Fatal(err)
	}
	// Normalize both descriptors: Windows abbreviates well-known account SIDs
	// (including the hosted runner's local Administrator account) in SDDL.
	expected, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	want := expected.String()
	if sd.String() != want {
		t.Fatalf("pipe ACL %s want %s", sd.String(), want)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{0, 0, 0, 1, 11})
	got := make([]byte, 5)
	if _, err = io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	p.closeConnections()
	if _, err = c.Read(got); err == nil {
		t.Fatal("active pipe survived shutdown")
	}
}

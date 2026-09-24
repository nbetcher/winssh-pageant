//go:build windows

package pageant

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/ndbeals/winssh-pageant/openssh"
	"golang.org/x/sys/windows"
)

func TestClientTargetArguments(t *testing.T) {
	for _, test := range []struct {
		app        string
		args       []string
		user, host string
		port       uint16
	}{
		{"plink.exe", []string{"-ssh", "-P", "2222", "-l", "dev", "example.test"}, "dev", "example.test", 2222},
		{"putty.exe", []string{"dev@example.test"}, "dev", "example.test", 0},
		{"putty.exe", []string{"dev@example.test", "-P", "2222"}, "dev", "example.test", 2222},
		{"ssh.exe", []string{"-vvv", "-p2222", "-ldev", "example.test", "echo", "-l", "not-user"}, "dev", "example.test", 2222},
		{"ssh.exe", []string{"-o", "User=dev", "-o", "HostName=example.test", "-o", "Port=2222", "alias"}, "dev", "example.test", 2222},
		{"ssh.exe", []string{"ssh://dev@[2001:db8::1]:2222"}, "dev", "2001:db8::1", 2222},
		{"plink.exe", []string{"-pw", "do-not-display", "-P", "2222", "dev@[2001:db8::1]"}, "dev", "2001:db8::1", 2222},
		{"plink.exe", []string{"-pwfile", "C:\\secret-file", "dev@example.test"}, "dev", "example.test", 0},
		{"plink.exe", []string{"-proxycmd", "command containing token", "dev@example.test"}, "dev", "example.test", 0},
		{"ssh.exe", []string{"--", "dev@example.test"}, "dev", "example.test", 0},
	} {
		target := parseClientTarget(test.app, test.args)
		if target.user != test.user || target.host != test.host || target.port != test.port {
			t.Fatalf("%s %v: got %+v", test.app, test.args, target)
		}
	}
}

func TestClientTargetRejectsAmbiguousOrUnsafeArguments(t *testing.T) {
	for _, test := range []struct {
		app  string
		args []string
	}{
		{"unknown.exe", []string{"dev@example.test"}},
		{"plink.exe", []string{"-unknown", "maybe-password", "dev@example.test"}},
		{"plink.exe", []string{"-pw"}},
		{"plink.exe", []string{"-P", "0", "example.test"}},
		{"ssh.exe", []string{"-p", "65536", "example.test"}},
		{"ssh.exe", []string{"ssh://dev:password@example.test"}},
		{"ssh.exe", []string{"example.test\nforged text"}},
		{"ssh.exe", []string{"example.test\u202eevil"}},
		{"ssh.exe", []string{"host:2222"}},
	} {
		if got := parseClientTarget(test.app, test.args); got.host != "" {
			t.Fatalf("accepted %s %v: %+v", test.app, test.args, got)
		}
	}
}

func TestClientProcessAndMappingAttribution(t *testing.T) {
	pid := uint32(os.Getpid())
	client := clientFromProcess(pid)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if client.pid != pid || !strings.EqualFold(client.name, filepath.Base(executable)) || client.started == 0 || client.inferred {
		t.Fatalf("incorrect process attribution: %+v", client)
	}
	process, err := ownProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	line := processCommandLine(process)
	if !strings.Contains(strings.ToLower(line), strings.ToLower(filepath.Base(executable))) {
		t.Fatal("could not read own bounded command line")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	client = clientFromMapping(fmt.Sprintf("PageantRequest%08x", windows.GetCurrentThreadId()))
	if client.pid != pid || !client.inferred {
		t.Fatalf("incorrect mapping hint: %+v", client)
	}
	for _, name := range []string{"", "PageantRequest00000000", "PageantRequest0000000z", "PageantRequest123456789", "arbitrary"} {
		if got := clientFromMapping(name); got.pid != 0 {
			t.Fatalf("accepted mapping %q", name)
		}
	}
	if got := clientFromProcess(0); got.pid != 0 {
		t.Fatal("accepted missing process")
	}
}

func TestNamedPipeClientProcessIdentity(t *testing.T) {
	pipe := fmt.Sprintf(`\\.\pipe\winssh-pageant-client-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	result := make(chan clientInfo, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- clientInfo{}
			return
		}
		defer func() { _ = conn.Close() }()
		result <- clientFromPipe(conn)
	}()
	conn, err := winio.DialPipe(pipe, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case client := <-result:
		if client.pid != uint32(os.Getpid()) || client.inferred || client.name == "" {
			t.Fatalf("incorrect kernel pipe PID: %+v", client)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client identification timed out")
	}
}

func TestSigningNoticeHonestTargetAndOutcome(t *testing.T) {
	sign := openssh.SignRequest{Username: "dev", Fingerprint: "SHA256:example"}
	client := clientInfo{pid: 123, name: "plink.exe", inferred: true}
	title, body := signingNotice(sign, []byte{0, 0, 0, 1, 14}, client, connectionTarget{user: "dev", host: "2001:db8::1", port: 2222, source: "client arguments"})
	if title != "SSH key used" || !strings.Contains(body, "dev@[2001:db8::1]:2222") || !strings.Contains(body, "inferred from mapping") || !strings.Contains(body, "client arguments") {
		t.Fatalf("incorrect notice %q: %q", title, body)
	}
	_, body = signingNotice(sign, []byte{0, 0, 0, 1, 14}, client, connectionTarget{user: "dev", host: "example.test", port: 22})
	if strings.Contains(body, ":22") {
		t.Fatalf("default port shown: %q", body)
	}
	title, body = signingNotice(sign, []byte{0, 0, 0, 1, 5}, clientInfo{}, connectionTarget{})
	if title != "SSH key request failed" || !strings.Contains(body, "Application unavailable") || !strings.Contains(body, "dev@unknown host") {
		t.Fatalf("incorrect failure %q: %q", title, body)
	}
	_, body = signingNotice(openssh.SignRequest{}, nil, clientInfo{}, connectionTarget{})
	if !strings.Contains(body, "Target unavailable") {
		t.Fatalf("invented target: %q", body)
	}
}

func TestTCPTableParsers(t *testing.T) {
	for _, family := range []uint32{windows.AF_INET, windows.AF_INET6} {
		size := 24
		if family == windows.AF_INET6 {
			size = 56
		}
		table := make([]byte, 4+size)
		binary.LittleEndian.PutUint32(table, 1)
		row := table[4:]
		want := "192.0.2.1"
		if family == windows.AF_INET {
			binary.LittleEndian.PutUint32(row, 5)
			copy(row[12:16], net.ParseIP(want).To4())
			binary.BigEndian.PutUint16(row[16:18], 2222)
			binary.LittleEndian.PutUint32(row[20:], 123)
		} else {
			want = "2001:db8::1"
			copy(row[24:40], net.ParseIP(want).To16())
			binary.BigEndian.PutUint16(row[44:46], 2222)
			binary.LittleEndian.PutUint32(row[48:], 5)
			binary.LittleEndian.PutUint32(row[52:], 123)
		}
		got, ok := parseTCPTable(table, 123, family)
		if !ok || len(got) != 1 || got[0].host != want || got[0].port != 2222 {
			t.Fatalf("family %d: %+v, %v", family, got, ok)
		}
		got, ok = parseTCPTable(table, 124, family)
		if !ok || len(got) != 0 {
			t.Fatal("included another process")
		}
		if _, ok := parseTCPTable(table[:len(table)-1], 123, family); ok {
			t.Fatal("accepted truncated table")
		}
		binary.LittleEndian.PutUint32(table, ^uint32(0))
		if _, ok := parseTCPTable(table, 123, family); ok {
			t.Fatal("accepted huge row count")
		}
	}
}

func TestTCPChildHelper(t *testing.T) {
	address := os.Getenv("WINSSH_PAGEANT_TCP_HELPER")
	if address == "" {
		return
	}
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestUniqueTCPClientLiveEndpoint(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestTCPChildHelper$")
	cmd.Env = append(os.Environ(), "WINSSH_PAGEANT_TCP_HELPER="+listener.Addr().String())
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	target, ok := uniqueTCPTarget(uint32(cmd.Process.Pid))
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	if !ok || target.host != "127.0.0.1" || strconv.Itoa(int(target.port)) != port || target.source != "inferred network endpoint" {
		t.Fatalf("actual child socket mismatch: %+v, %v", target, ok)
	}
	if _, err := conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

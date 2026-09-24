//go:build windows

package pageant

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func TestBridgeBindingLifetimeAndInterruptedShutdown(t *testing.T) {
	prefix := fmt.Sprintf(`\\.\pipe\winssh-binding-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	upstream, err := listenUserPipe(prefix + "-upstream")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstream.Close() }()
	downstream, err := listenUserPipe(prefix + "-bridge")
	if err != nil {
		t.Fatal(err)
	}
	p := NewDefaultHandler(prefix+"-upstream", true)
	p.state = &runtimeState{listener: downstream, clients: make(map[net.Conn]struct{})}
	defer p.closeConnections()
	boundRequest := signingFrame(append([]byte{27}, signingString([]byte("session-bind@openssh.com"))...))
	listRequest := []byte{0, 0, 0, 1, 11}
	listReply := []byte{0, 0, 0, 5, 12, 0, 0, 0, 0}
	stalled := make(chan struct{})
	agentDone := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			agentDone <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			agentDone <- err
			return
		}
		request, err := signingReadFrame(conn)
		if err != nil {
			agentDone <- err
			return
		}
		if !bytes.Equal(request, boundRequest) {
			agentDone <- fmt.Errorf("expected session binding")
			return
		}
		if _, err := conn.Write([]byte{0, 0, 0, 1, 6}); err != nil {
			agentDone <- err
			return
		}
		request, err = signingReadFrame(conn)
		if err != nil {
			agentDone <- fmt.Errorf("session lost after bind: %w", err)
			return
		}
		if !bytes.Equal(request, listRequest) {
			agentDone <- fmt.Errorf("unexpected second request")
			return
		}
		if _, err := conn.Write(listReply); err != nil {
			agentDone <- err
			return
		}
		if _, err := signingReadFrame(conn); err != nil {
			agentDone <- err
			return
		}
		close(stalled) // Request consumed; deliberately wait without replying.
		var b [1]byte
		if _, err := conn.Read(b[:]); err == nil {
			agentDone <- fmt.Errorf("upstream survived shutdown")
			return
		}
		agentDone <- nil
	}()
	go p.pipeProxy()
	client, err := winio.DialPipe(prefix+"-bridge", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for i, request := range [][]byte{boundRequest, listRequest} {
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		reply, err := signingReadFrame(client)
		if err != nil {
			t.Fatal(err)
		}
		want := []byte{0, 0, 0, 1, 6}
		if i == 1 {
			want = listReply
		}
		if !bytes.Equal(reply, want) {
			t.Fatalf("request %d reply %v want %v", i, reply, want)
		}
	}
	if _, err := client.Write(listRequest); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stalled:
	case err := <-agentDone:
		t.Fatalf("upstream failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received third request")
	}
	closed := make(chan struct{})
	go func() { p.closeConnections(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked on an unanswered upstream request")
	}
	if _, err := io.ReadFull(client, make([]byte, 1)); err == nil {
		t.Fatal("downstream survived shutdown")
	}
	select {
	case err := <-agentDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not close upstream")
	}
}

//go:build windows

package openssh

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

func frame(payload []byte) []byte {
	result := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(result, uint32(len(payload)))
	return append(result, payload...)
}

func TestQueryAgentRejectsMalformedRequests(t *testing.T) {
	for _, request := range [][]byte{
		nil, {}, {0, 0, 0, 0}, {0, 0, 0, 0, 11}, {0, 0, 0, 2, 11},
		frame(make([]byte, AgentMaxMessageLength-3)),
	} {
		got, err := QueryAgent(`\\.\pipe\winssh-pageant-nonexistent-test`, request)
		if err == nil || !bytes.Equal(got, genericFailResponse()) {
			t.Fatalf("request of %d bytes: got %v, %v", len(request), got, err)
		}
	}
}

func TestValidateFrameBoundaries(t *testing.T) {
	if err := ValidateRequest(frame(make([]byte, AgentMaxMessageLength-4))); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(frame(make([]byte, AgentMaxResponseLength))); err != nil {
		t.Fatal(err)
	}
	if err := ValidateResponse(frame(make([]byte, AgentMaxResponseLength+1))); err == nil {
		t.Fatal("accepted oversized reply")
	}
	if err := ValidateResponse(frame([]byte{SSH_AGENT_FAIL, 0})); err == nil {
		t.Fatal("accepted padded failure")
	}
}

func TestQueryAgentRejectsRemotePipes(t *testing.T) {
	for _, name := range []string{`\\server\pipe\agent`, `C:\file`, `\\.\pipe\`, "\\\\.\\pipe\\bad\x00name"} {
		_, err := QueryAgent(name, frame([]byte{11}))
		if err == nil || !strings.Contains(err.Error(), "local") {
			t.Fatalf("pipe %q: %v", name, err)
		}
	}
}

type fakeConn struct {
	reader           io.Reader
	written          bytes.Buffer
	maxWrite         int
	zeroWrite        bool
	writeErr         error
	writeDeadlineErr error
	readDeadlineErr  error
	writeDeadline    time.Time
	readDeadline     time.Time
}

func (c *fakeConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.zeroWrite {
		return 0, nil
	}
	if c.maxWrite > 0 && len(p) > c.maxWrite {
		p = p[:c.maxWrite]
	}
	return c.written.Write(p)
}
func (*fakeConn) Close() error                { return nil }
func (*fakeConn) LocalAddr() net.Addr         { return nil }
func (*fakeConn) RemoteAddr() net.Addr        { return nil }
func (*fakeConn) SetDeadline(time.Time) error { return errors.New("unexpected combined deadline") }
func (c *fakeConn) SetReadDeadline(deadline time.Time) error {
	c.readDeadline = deadline
	return c.readDeadlineErr
}
func (c *fakeConn) SetWriteDeadline(deadline time.Time) error {
	c.writeDeadline = deadline
	return c.writeDeadlineErr
}

type fragmentReader struct{ data []byte }

func (r *fragmentReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestExchangeHandlesPartialIOAndLargeReply(t *testing.T) {
	request := frame([]byte{11})
	reply := frame(bytes.Repeat([]byte{12}, 32000))
	conn := &fakeConn{reader: &fragmentReader{data: reply}, maxWrite: 2}
	start := time.Now()
	got, err := exchange(conn, request)
	if err != nil || !bytes.Equal(got, reply) || !bytes.Equal(conn.written.Bytes(), request) {
		t.Fatalf("partial I/O failed: reply length %d, request %v, err %v", len(got), conn.written.Bytes(), err)
	}
	if conn.writeDeadline.Before(start) || conn.readDeadline.Before(start) {
		t.Fatal("deadlines were not set")
	}
}

func TestExchangeReportsFailures(t *testing.T) {
	sentinel := errors.New("test I/O error")
	oversized := make([]byte, 4)
	binary.BigEndian.PutUint32(oversized, AgentMaxResponseLength+1)
	for name, conn := range map[string]*fakeConn{
		"write deadline":   {reader: bytes.NewReader(nil), writeDeadlineErr: sentinel},
		"read deadline":    {reader: bytes.NewReader(nil), readDeadlineErr: sentinel},
		"write":            {reader: bytes.NewReader(nil), writeErr: sentinel},
		"zero write":       {reader: bytes.NewReader(nil), zeroWrite: true},
		"truncated prefix": {reader: bytes.NewReader([]byte{0, 0})},
		"truncated body":   {reader: bytes.NewReader([]byte{0, 0, 0, 2, 12})},
		"zero body":        {reader: bytes.NewReader([]byte{0, 0, 0, 0})},
		"huge body":        {reader: bytes.NewReader(oversized)},
		"failure padding":  {reader: bytes.NewReader(frame([]byte{SSH_AGENT_FAIL, 0}))},
	} {
		t.Run(name, func(t *testing.T) {
			reply, err := exchange(conn, frame([]byte{11}))
			if err == nil || !bytes.Equal(reply, genericFailResponse()) {
				t.Fatalf("got %v, %v", reply, err)
			}
		})
	}
}

func TestAgentRefusalIsNormalReply(t *testing.T) {
	conn := &fakeConn{reader: bytes.NewReader(genericFailResponse())}
	got, err := exchange(conn, frame([]byte{11}))
	if err != nil || !bytes.Equal(got, genericFailResponse()) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestQueryAgentRealNamedPipe(t *testing.T) {
	pipe := fmt.Sprintf(`\\.\pipe\winssh-pageant-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	done := make(chan error, 1)
	request := frame([]byte{11})
	reply := frame([]byte{12, 0, 0, 0, 0})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		got := make([]byte, len(request))
		if _, err := io.ReadFull(conn, got); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(got, request) {
			done <- fmt.Errorf("unexpected request")
			return
		}
		for _, b := range reply {
			if _, err := conn.Write([]byte{b}); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	got, err := QueryAgent(pipe, request)
	if err != nil || !bytes.Equal(got, reply) {
		t.Fatalf("got %v, %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLiveOpenSSHKeys(t *testing.T) {
	if os.Getenv("WINSSH_PAGEANT_TEST_LIVE_AGENT") != "1" {
		t.Skip("set WINSSH_PAGEANT_TEST_LIVE_AGENT=1 to query the installed agent read-only")
	}
	keys, err := ListKeys(`\\.\pipe\openssh-ssh-agent`)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("installed Windows OpenSSH agent returned %d keys", len(keys))
}

func TestOneShotRejectsSessionBinding(t *testing.T) {
	request := frame(append([]byte{27}, sshString([]byte("session-bind@openssh.com"))...))
	reply, err := QueryAgent(`\\.\pipe\not-opened`, request)
	if err == nil || !strings.Contains(err.Error(), "persistent") || !bytes.Equal(reply, genericFailResponse()) {
		t.Fatalf("one-shot binding was not explicitly rejected: %v, %v", reply, err)
	}
}

func TestSessionPreservesUpstreamConnection(t *testing.T) {
	pipe := fmt.Sprintf(`\\.\pipe\winssh-pageant-session-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	listener, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		for i := 0; i < 2; i++ {
			var header [4]byte
			if _, err := io.ReadFull(conn, header[:]); err != nil {
				done <- err
				return
			}
			payload := make([]byte, binary.BigEndian.Uint32(header[:]))
			if _, err := io.ReadFull(conn, payload); err != nil {
				done <- err
				return
			}
			if i == 0 && payload[0] != 27 {
				done <- fmt.Errorf("expected bind request")
				return
			}
			if i == 1 && payload[0] != 11 {
				done <- fmt.Errorf("expected identities request")
				return
			}
			if _, err := conn.Write(frame([]byte{6})); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	session := NewSession(pipe)
	defer func() { _ = session.Close() }()
	for _, request := range [][]byte{
		frame(append([]byte{27}, sshString([]byte("session-bind@openssh.com"))...)),
		frame([]byte{11}),
	} {
		if reply, err := session.Query(request); err != nil || !bytes.Equal(reply, frame([]byte{6})) {
			t.Fatalf("got %v, %v", reply, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSessionCloseInterruptsResponseAndNeverReconnects(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	session := NewSession(`\\.\pipe\not-opened`)
	session.conn = client
	done := make(chan error, 1)
	go func() { _, err := session.Query(frame([]byte{11})); done <- err }()
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(server, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed query succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not interrupt a blocked reply")
	}
	if _, err := session.Query(frame([]byte{11})); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("session attempted silent reconnect: %v", err)
	}
}

func TestSessionTransportFailureIsTerminal(t *testing.T) {
	session := NewSession(`\\.\pipe\not-opened`)
	session.conn = &fakeConn{reader: bytes.NewReader([]byte{0, 0})}
	if _, err := session.Query(frame([]byte{11})); err == nil {
		t.Fatal("truncated reply succeeded")
	}
	if _, err := session.Query(frame([]byte{11})); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("transport failure did not retire session: %v", err)
	}
}

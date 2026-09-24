//go:build windows

package openssh

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Microsoft/go-winio"
)

const (
	// AgentMaxMessageLength includes the four-byte length prefix. This limit
	// also bounds requests received over Pageant's shared-memory transport.
	AgentMaxMessageLength = 1<<14 - 1
	// AgentMaxResponseLength bounds the reply payload, excluding its prefix.
	// Key lists may be larger than requests; never trust the agent's length.
	AgentMaxResponseLength      = 256 * 1024
	SSH_AGENT_FAIL         byte = 5

	agentConnectTimeout  = 2 * time.Second
	agentWriteTimeout    = 2 * time.Second
	agentResponseTimeout = 60 * time.Second
)

// genericFailResponse returns an independently owned SSH_AGENT_FAILURE frame.
func genericFailResponse() []byte {
	return []byte{0, 0, 0, 1, SSH_AGENT_FAIL}
}

// QueryAgent forwards one complete, length-prefixed request to a local Windows
// OpenSSH agent. Operational and malformed-message failures return both a valid
// failure frame and a non-nil error. An agent's own refusal is a normal reply.
// No request contents or key material are logged here.
func QueryAgent(pipeName string, request []byte) ([]byte, error) {
	if ValidateRequest(request) == nil && isSessionBind(request) {
		return genericFailResponse(), fmt.Errorf("session binding requires a persistent agent connection")
	}
	session := NewSession(pipeName)
	defer func() { _ = session.Close() }()
	return session.Query(request)
}

// Session keeps one upstream agent connection for one downstream pipe client.
// Agent extensions such as session-bind@openssh.com attach security state to
// that connection. A failed connection is never silently reconnected.
type Session struct {
	queryMu  sync.Mutex
	stateMu  sync.Mutex
	pipeName string
	conn     net.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
}

// NewSession creates a lazily connected session. Its owner must call Close.
func NewSession(pipeName string) *Session {
	ctx, cancel := context.WithCancel(context.Background())
	return &Session{pipeName: pipeName, ctx: ctx, cancel: cancel}
}

// Query exchanges one framed request. Calls are serialized in wire order;
// Close may run concurrently and interrupts an in-progress connect or read.
func (s *Session) Query(request []byte) ([]byte, error) {
	s.queryMu.Lock()
	defer s.queryMu.Unlock()
	if err := ValidateRequest(request); err != nil {
		return genericFailResponse(), fmt.Errorf("invalid agent request: %w", err)
	}
	if !localPipeName(s.pipeName) {
		return genericFailResponse(), fmt.Errorf("agent pipe must be a local \\\\.\\pipe\\ name")
	}
	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return genericFailResponse(), fmt.Errorf("OpenSSH agent session is closed")
	}
	conn := s.conn
	s.stateMu.Unlock()
	if conn == nil {
		ctx, cancel := context.WithTimeout(s.ctx, agentConnectTimeout)
		var err error
		conn, err = winio.DialPipeContext(ctx, s.pipeName)
		cancel()
		if err != nil {
			_ = s.Close()
			return genericFailResponse(), fmt.Errorf("connect to OpenSSH agent: %w", err)
		}
		s.stateMu.Lock()
		if s.closed {
			s.stateMu.Unlock()
			_ = conn.Close()
			return genericFailResponse(), fmt.Errorf("OpenSSH agent session is closed")
		}
		s.conn = conn
		s.stateMu.Unlock()
	}
	reply, err := exchange(conn, request)
	if err != nil {
		_ = s.Close()
	}
	return reply, err
}

// Close prevents further queries and releases the upstream pipe.
func (s *Session) Close() error {
	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return nil
	}
	s.closed = true
	s.cancel()
	conn := s.conn
	s.conn = nil
	s.stateMu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func isSessionBind(request []byte) bool {
	if request[4] != 27 {
		return false
	} // SSH_AGENTC_EXTENSION
	remaining := request[5:]
	name, ok := takeString(&remaining)
	return ok && string(name) == "session-bind@openssh.com"
}

func localPipeName(name string) bool {
	lower := strings.ToLower(name)
	return (strings.HasPrefix(lower, `\\.\pipe\`) || strings.HasPrefix(lower, `\\?\pipe\`)) &&
		len(name) > len(`\\.\pipe\`) && !strings.ContainsRune(name, 0)
}

// ValidateRequest checks the complete framed request before forwarding it.
func ValidateRequest(frame []byte) error {
	return validateFrame(frame, AgentMaxMessageLength-4)
}

// ValidateResponse checks the complete framed reply before forwarding it.
func ValidateResponse(frame []byte) error {
	if err := validateFrame(frame, AgentMaxResponseLength); err != nil {
		return err
	}
	if frame[4] == SSH_AGENT_FAIL && len(frame) != 5 {
		return fmt.Errorf("malformed agent failure reply")
	}
	return nil
}

func validateFrame(frame []byte, maxPayload int) error {
	if len(frame) < 5 {
		return fmt.Errorf("message must include a length and type")
	}
	if len(frame)-4 > maxPayload {
		return fmt.Errorf("message exceeds %d bytes", maxPayload)
	}
	if binary.BigEndian.Uint32(frame[:4]) != uint32(len(frame)-4) {
		return fmt.Errorf("message length does not match its frame")
	}
	return nil
}

func exchange(conn net.Conn, request []byte) ([]byte, error) {
	fail := func(operation string, err error) ([]byte, error) {
		return genericFailResponse(), fmt.Errorf("%s: %w", operation, err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(agentWriteTimeout)); err != nil {
		return fail("set agent write deadline", err)
	}
	for remaining := request; len(remaining) > 0; {
		n, err := conn.Write(remaining)
		if err != nil {
			return fail("write agent request", err)
		}
		if n <= 0 || n > len(remaining) {
			return fail("write agent request", io.ErrShortWrite)
		}
		remaining = remaining[n:]
	}
	// Hardware-backed keys may need user interaction. The deadline covers the
	// entire reply, so a peer cannot keep a goroutine alive by trickling bytes.
	if err := conn.SetReadDeadline(time.Now().Add(agentResponseTimeout)); err != nil {
		return fail("set agent read deadline", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fail("read agent reply length", err)
	}
	payloadLength := binary.BigEndian.Uint32(header[:])
	if payloadLength == 0 || payloadLength > AgentMaxResponseLength {
		return genericFailResponse(), fmt.Errorf("invalid agent reply length %d", payloadLength)
	}
	reply := make([]byte, 4+int(payloadLength))
	copy(reply, header[:])
	if _, err := io.ReadFull(conn, reply[4:]); err != nil {
		return fail("read agent reply", err)
	}
	if err := ValidateResponse(reply); err != nil {
		return genericFailResponse(), err
	}
	return reply, nil
}

package openssh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Microsoft/go-winio"
)

const (
	// AgentMaxMessageLength is the maximum length of a request sent to the agent.
	AgentMaxMessageLength = 1<<14 - 1 // 16383
	// AgentMaxResponseLength bounds the agent's reply. Replies (e.g. an
	// identities-answer listing many keys) are legitimately far larger than a
	// request, so they must not be limited to AgentMaxMessageLength; 256 KiB
	// matches the ssh-agent protocol's practical maximum message size while
	// still rejecting a malformed/hostile size that would otherwise allocate
	// gigabytes.
	AgentMaxResponseLength      = 256 * 1024
	SSH_AGENT_FAIL         byte = 0x05
)

// genericFailResponse returns a fresh SSH_AGENT_FAILURE reply. A new slice is
// allocated on every call so callers can never mutate a shared sentinel.
func genericFailResponse() []byte {
	return []byte{0x00, 0x00, 0x00, 0x01, SSH_AGENT_FAIL}
}

// QueryAgent provides a way to query the named windows openssh agent pipe
func QueryAgent(pipeName string, buf []byte) (result []byte, err error) {
	if len(buf) > AgentMaxMessageLength {
		fmt.Println("message too long")
		return genericFailResponse(), nil
	}

	conn, err := winio.DialPipe(pipeName, nil)
	if err != nil {
		fmt.Printf("cannot connect to pipe %s: %s\n", pipeName, err.Error())
		return genericFailResponse(), nil
	}
	defer conn.Close()
	// If the agent needs the user to do something, give them time to do so, but don't wait forever.
	conn.SetDeadline(time.Now().Add(time.Second * 2))

	_, err = conn.Write(buf)
	if err != nil {
		fmt.Printf("cannot write ssh client request to agent pipe %s: %s\n", pipeName, err.Error())
		return genericFailResponse(), nil
	}

	conn.SetDeadline(time.Now().Add(time.Second * 60)) // Update deadline
	// <https://github.com/openssh/openssh-portable/blob/4e636cf/PROTOCOL.agent>
	// first 4 bytes are messageSizeBuf uint32
	messageSizeBuf := make([]byte, 4)
	_, err = io.ReadFull(conn, messageSizeBuf)
	if err != nil {
		switch {
		case errors.Is(err, winio.ErrTimeout):
			fmt.Printf("Timeout waiting for user input %s: %s\n", pipeName, err.Error())
		default:
			fmt.Printf("Cannot read message size from pipe %s: %s\n", pipeName, err.Error())
		}
		return genericFailResponse(), nil
	}
	messageSize := binary.BigEndian.Uint32(messageSizeBuf)

	// The reply must hold at least the type byte and must not exceed the
	// protocol maximum. A zero size would also underflow the messageContents
	// allocation below, and an unbounded size would allocate up to ~4 GiB.
	// Note this bounds the REPLY (AgentMaxResponseLength), not the request.
	if messageSize < 1 || messageSize > AgentMaxResponseLength {
		fmt.Printf("invalid message size %d from pipe %s\n", messageSize, pipeName)
		return genericFailResponse(), nil
	}

	// next byte is the reply type code
	replyCode := make([]byte, 1)
	_, err = io.ReadFull(conn, replyCode)
	if err != nil {
		fmt.Printf("Cannot read message type from pipe %s: %s\n", pipeName, err.Error())
		return genericFailResponse(), nil
	}
	if replyCode[0] == SSH_AGENT_FAIL {
		return append(messageSizeBuf, replyCode...), nil
	}

	// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-3
	messageContents := make([]byte, messageSize-1)
	_, err = io.ReadFull(conn, messageContents)
	if err != nil {
		fmt.Printf("cannot read message contents from pipe %s: %s\n", pipeName, err.Error())
		return genericFailResponse(), nil
	}

	concatResults := append(messageSizeBuf, replyCode...)
	concatResults = append(concatResults, messageContents...)

	return concatResults, nil
}

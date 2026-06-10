package openssh

import (
	"bytes"
	"testing"
)

// TestQueryAgentRejectsOversizedRequest verifies the request-size guard returns
// a well-formed SSH_AGENT_FAILURE without attempting to dial the agent pipe.
func TestQueryAgentRejectsOversizedRequest(t *testing.T) {
	req := make([]byte, AgentMaxMessageLength+1)
	got, err := QueryAgent(`\\.\pipe\winssh-pageant-nonexistent-test`, req)
	if err != nil {
		t.Fatalf("QueryAgent returned error: %v", err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x01, SSH_AGENT_FAIL}
	if !bytes.Equal(got, want) {
		t.Errorf("QueryAgent oversized request = %v, want %v", got, want)
	}
}

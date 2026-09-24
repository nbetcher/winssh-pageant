//go:build windows

package openssh

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
)

const (
	agentRequestIdentities byte = 11
	agentIdentitiesAnswer  byte = 12
	agentSignRequest       byte = 13
)

// Key is public metadata for a key currently loaded in the upstream agent.
// It never contains a private key or a copy of the public-key blob.
type Key struct {
	Type        string
	Fingerprint string
	Comment     string
}

// ListKeys obtains a fresh list of the public keys loaded into the agent.
// Files that have not been added to the agent are intentionally not enumerated.
func ListKeys(pipeName string) ([]Key, error) {
	reply, err := QueryAgent(pipeName, []byte{0, 0, 0, 1, agentRequestIdentities})
	if err != nil {
		return nil, err
	}
	return parseKeys(reply)
}

func parseKeys(reply []byte) ([]Key, error) {
	if err := ValidateResponse(reply); err != nil {
		return nil, fmt.Errorf("invalid key list: %w", err)
	}
	if reply[4] == SSH_AGENT_FAIL {
		return nil, fmt.Errorf("the OpenSSH agent refused to list keys (it may be locked)")
	}
	if reply[4] != agentIdentitiesAnswer || len(reply) < 9 {
		return nil, fmt.Errorf("unexpected OpenSSH key-list reply")
	}
	count := binary.BigEndian.Uint32(reply[5:9])
	remaining := reply[9:]
	// Each entry needs at least two string lengths. Check before allocating so
	// a hostile count cannot force a large allocation from a small reply.
	if uint64(count) > uint64(len(remaining)/8) {
		return nil, fmt.Errorf("invalid OpenSSH key count")
	}
	keys := make([]Key, 0, int(count))
	for range count {
		blob, ok := takeString(&remaining)
		if !ok {
			return nil, fmt.Errorf("truncated OpenSSH public key")
		}
		comment, ok := takeString(&remaining)
		if !ok {
			return nil, fmt.Errorf("truncated OpenSSH key comment")
		}
		keyType, ok := publicKeyType(blob)
		if !ok {
			return nil, fmt.Errorf("malformed OpenSSH public key type")
		}
		keys = append(keys, Key{Type: keyType, Fingerprint: fingerprint(blob), Comment: displayText(comment, 1024)})
	}
	if len(remaining) != 0 {
		return nil, fmt.Errorf("trailing data in OpenSSH key list")
	}
	return keys, nil
}

// SignRequest contains only the public metadata needed for a notification.
// Username is filled only for a structurally valid SSH public-key userauth
// payload. It is supplied by the client, not verified against the SSH server.
// Hostname and port are not present in the standard agent signing protocol.
type SignRequest struct {
	KeyType     string
	Fingerprint string
	Username    string
}

// ParseSignRequest recognizes a complete sign request. Generic signature data
// (for example a Git commit) is valid but has no target username.
func ParseSignRequest(frame []byte) (SignRequest, bool) {
	if ValidateRequest(frame) != nil || frame[4] != agentSignRequest {
		return SignRequest{}, false
	}
	remaining := frame[5:]
	blob, ok := takeString(&remaining)
	if !ok {
		return SignRequest{}, false
	}
	data, ok := takeString(&remaining)
	if !ok || len(remaining) != 4 { // uint32 signature flags
		return SignRequest{}, false
	}
	keyType, ok := publicKeyType(blob)
	if !ok {
		return SignRequest{}, false
	}
	return SignRequest{KeyType: keyType, Fingerprint: fingerprint(blob), Username: userauthUsername(data, blob)}, true
}

func userauthUsername(data, signingKey []byte) string {
	// RFC 4252 section 7: session identifier, message 50, username, service,
	// method, true, signature algorithm, public key. OpenSSH's host-bound form
	// appends the server's host key, but still carries no hostname or port.
	session, ok := takeString(&data)
	if !ok || len(session) == 0 || len(data) == 0 || data[0] != 50 {
		return ""
	}
	data = data[1:]
	username, ok := takeString(&data)
	if !ok || len(username) == 0 {
		return ""
	}
	service, ok := takeString(&data)
	if !ok || string(service) != "ssh-connection" {
		return ""
	}
	method, ok := takeString(&data)
	hostbound := string(method) == "publickey-hostbound-v00@openssh.com"
	if !ok || (string(method) != "publickey" && !hostbound) || len(data) == 0 || data[0] != 1 {
		return ""
	}
	data = data[1:]
	algorithm, ok := takeString(&data)
	if !ok || len(algorithm) == 0 {
		return ""
	}
	key, ok := takeString(&data)
	if !ok || !bytes.Equal(key, signingKey) {
		return ""
	}
	if hostbound {
		hostKey, ok := takeString(&data)
		if !ok || len(hostKey) == 0 {
			return ""
		}
	}
	if len(data) != 0 {
		return ""
	}
	return displayText(username, 256)
}

func takeString(data *[]byte) ([]byte, bool) {
	if len(*data) < 4 {
		return nil, false
	}
	length := binary.BigEndian.Uint32((*data)[:4])
	if uint64(length) > uint64(len(*data)-4) {
		return nil, false
	}
	value := (*data)[4 : 4+int(length)]
	*data = (*data)[4+int(length):]
	return value, true
}

func publicKeyType(blob []byte) (string, bool) {
	keyType, ok := takeString(&blob)
	if !ok || len(keyType) == 0 || len(keyType) > 128 || len(blob) == 0 {
		return "", false
	}
	for _, b := range keyType {
		if b < 33 || b > 126 {
			return "", false
		}
	}
	return string(keyType), true
}

func fingerprint(blob []byte) string {
	hash := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(hash[:])
}

func displayText(value []byte, limit int) string {
	var text strings.Builder
	for count, r := range []rune(string(value)) {
		if count == limit {
			text.WriteRune('…')
			break
		}
		// Strip bidi/zero-width formatting and line separators as well as NUL
		// and other control characters before passing text to native controls.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			r = ' '
		}
		text.WriteRune(r)
	}
	return text.String()
}

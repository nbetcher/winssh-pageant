//go:build windows

package openssh

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func sshString(value []byte) []byte { return frame(value) }

func testPublicKey() []byte {
	return append(sshString([]byte("ssh-ed25519")), sshString(bytes.Repeat([]byte{42}, 32))...)
}

func identitiesReply(blob []byte, comment string) []byte {
	payload := []byte{agentIdentitiesAnswer, 0, 0, 0, 1}
	payload = append(payload, sshString(blob)...)
	payload = append(payload, sshString([]byte(comment))...)
	return frame(payload)
}

func signFrame(blob, data []byte) []byte {
	payload := append([]byte{agentSignRequest}, sshString(blob)...)
	payload = append(payload, sshString(data)...)
	return frame(append(payload, 0, 0, 0, 0))
}

func userauthData(blob []byte, username, method string) []byte {
	data := sshString(bytes.Repeat([]byte{7}, 32))
	data = append(data, 50)
	for _, field := range []string{username, "ssh-connection", method} {
		data = append(data, sshString([]byte(field))...)
	}
	data = append(data, 1)
	data = append(data, sshString([]byte("ssh-ed25519"))...)
	data = append(data, sshString(blob)...)
	return data
}

func TestParseKeys(t *testing.T) {
	keys, err := parseKeys(identitiesReply(testPublicKey(), "work key"))
	if err != nil || len(keys) != 1 {
		t.Fatalf("got %v, %v", keys, err)
	}
	if keys[0].Type != "ssh-ed25519" || keys[0].Comment != "work key" || !strings.HasPrefix(keys[0].Fingerprint, "SHA256:") || len(keys[0].Fingerprint) != 50 {
		t.Fatalf("incorrect key metadata: %+v", keys[0])
	}
	keys, err = parseKeys(frame([]byte{agentIdentitiesAnswer, 0, 0, 0, 0}))
	if err != nil || len(keys) != 0 {
		t.Fatalf("empty agent: got %v, %v", keys, err)
	}
}

func TestParseKeysSanitizesDisplayText(t *testing.T) {
	keys, err := parseKeys(identitiesReply(testPublicKey(), "work\x00\r\n\u202eevil\u2028line"))
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Comment != "work    evil line" {
		t.Fatalf("unsafe display text: %q", keys[0].Comment)
	}
	keys, err = parseKeys(identitiesReply(testPublicKey(), strings.Repeat("é", 1200)))
	if err != nil {
		t.Fatal(err)
	}
	if len([]rune(keys[0].Comment)) != 1025 || !strings.HasSuffix(keys[0].Comment, "…") {
		t.Fatal("long comment was not bounded safely at a rune boundary")
	}
}

func TestParseKeysRejectsMalformedReplies(t *testing.T) {
	valid := identitiesReply(testPublicKey(), "comment")
	for _, reply := range [][]byte{
		nil, genericFailResponse(), frame([]byte{6}), frame([]byte{12}),
		frame([]byte{12, 255, 255, 255, 255}),
		frame([]byte{12, 0, 0, 0, 0, 0}),
		identitiesReply(nil, "comment"), identitiesReply(sshString([]byte("ssh-ed25519")), "comment"),
		identitiesReply(append(sshString([]byte("invalid\x00type")), 1), "comment"),
		frame(append(valid[4:], 0)),
	} {
		if _, err := parseKeys(reply); err == nil {
			t.Fatalf("accepted malformed identities reply %x", reply)
		}
	}
	// Every truncation of a valid answer must fail, even if its outer framing
	// is rewritten to match; otherwise a partial list could look complete.
	for i := 0; i < len(valid)-4; i++ {
		if _, err := parseKeys(frame(valid[4 : 4+i])); err == nil {
			t.Fatalf("accepted truncated reply at %d", i)
		}
	}
}

func TestParseSignRequestUsername(t *testing.T) {
	blob := testPublicKey()
	for _, method := range []string{"publickey", "publickey-hostbound-v00@openssh.com"} {
		data := userauthData(blob, "developer", method)
		if method != "publickey" {
			data = append(data, sshString(blob)...)
		}
		sign, ok := ParseSignRequest(signFrame(blob, data))
		if !ok || sign.Username != "developer" || sign.KeyType != "ssh-ed25519" || len(sign.Fingerprint) != 50 {
			t.Fatalf("method %s: %+v, %v", method, sign, ok)
		}
	}
}

func TestParseSignRequestDoesNotInventTarget(t *testing.T) {
	blob := testPublicKey()
	validData := userauthData(blob, "developer", "publickey")
	for name, data := range map[string][]byte{
		"arbitrary data":   []byte("git signature or arbitrary data"),
		"trailing data":    append(append([]byte(nil), validData...), 0),
		"wrong key":        userauthData(append(append([]byte(nil), blob...), 0), "developer", "publickey"),
		"wrong method":     userauthData(blob, "developer", "password"),
		"missing host key": userauthData(blob, "developer", "publickey-hostbound-v00@openssh.com"),
	} {
		t.Run(name, func(t *testing.T) {
			sign, ok := ParseSignRequest(signFrame(blob, data))
			if !ok || sign.Username != "" {
				t.Fatalf("got %+v, %v", sign, ok)
			}
		})
	}
	for i := 0; i < len(validData); i++ {
		sign, ok := ParseSignRequest(signFrame(blob, validData[:i]))
		if !ok || sign.Username != "" {
			t.Fatalf("partial auth data %d: %+v, %v", i, sign, ok)
		}
	}
}

func TestParseSignRequestRejectsMalformedFrame(t *testing.T) {
	valid := signFrame(testPublicKey(), []byte("data"))
	for i := 0; i < len(valid); i++ {
		if _, ok := ParseSignRequest(valid[:i]); ok {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	for _, request := range [][]byte{
		frame([]byte{11}), frame(append(valid[4:], 0)),
		signFrame(nil, []byte("data")),
		frame([]byte{13, 255, 255, 255, 255}),
	} {
		if _, ok := ParseSignRequest(request); ok {
			t.Fatalf("accepted malformed sign request")
		}
	}
}

func FuzzProtocolMetadata(f *testing.F) {
	f.Add(identitiesReply(testPublicKey(), "test"))
	f.Add(signFrame(testPublicKey(), userauthData(testPublicKey(), "user", "publickey")))
	f.Add([]byte{0, 0, 0, 1, 5})
	f.Fuzz(func(t *testing.T, data []byte) {
		// The wire length and nested SSH strings are all attacker-controlled.
		// Exercise both mismatched and matching top-level lengths.
		_, _ = parseKeys(data)
		_, _ = ParseSignRequest(data)
		if len(data) <= AgentMaxResponseLength && len(data) >= 5 {
			copyData := append([]byte(nil), data...)
			binary.BigEndian.PutUint32(copyData, uint32(len(copyData)-4))
			_, _ = parseKeys(copyData)
			_, _ = ParseSignRequest(copyData)
		}
	})
}

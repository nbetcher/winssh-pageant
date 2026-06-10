package pageant

import (
	"errors"
	"testing"
)

func TestNewWithOptions(t *testing.T) {
	tests := []struct {
		name            string
		opts            []Option
		wantSSHPipe     string
		wantPageantPipe bool
	}{
		{"defaults", nil, DefaultSSHAgentPipe, true},
		{"an-ssh-pipe", []Option{WithSSHPipe(`\\.\an-ssh-pipe\`)}, `\\.\an-ssh-pipe\`, true},
		{"no-pageant-pipe", []Option{WithPageantPipe(false)}, DefaultSSHAgentPipe, false},
		{"two-pipes", []Option{WithSSHPipe(`\\.\an-ssh-pipe\`), WithPageantPipe(false)}, `\\.\an-ssh-pipe\`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewWithOptions(tt.opts...)
			if got.SSHAgentPipe != tt.wantSSHPipe {
				t.Errorf("NewWithOptions() SSHAgentPipe = %q, want %q", got.SSHAgentPipe, tt.wantSSHPipe)
			}
			if got.pageantPipe != tt.wantPageantPipe {
				t.Errorf("NewWithOptions() pageantPipe = %v, want %v", got.pageantPipe, tt.wantPageantPipe)
			}
			if got.PageantRequestHandler == nil {
				t.Error("NewWithOptions() PageantRequestHandler is nil, want the default handler")
			}
		})
	}
}

func TestNew(t *testing.T) {
	want := errors.New("custom")
	handler := func(_ *Pageant, _ []byte) ([]byte, error) {
		return nil, want
	}

	got := New(`\\.\custom-pipe\`, false, handler)
	if got.SSHAgentPipe != `\\.\custom-pipe\` {
		t.Errorf("New() SSHAgentPipe = %q, want %q", got.SSHAgentPipe, `\\.\custom-pipe\`)
	}
	if got.pageantPipe {
		t.Error("New() pageantPipe = true, want false")
	}
	if got.PageantRequestHandler == nil {
		t.Fatal("New() PageantRequestHandler is nil")
	}
	if _, err := got.PageantRequestHandler(got, nil); !errors.Is(err, want) {
		t.Errorf("New() stored the wrong handler: got err %v, want %v", err, want)
	}
}

func TestNewDefaultHandler(t *testing.T) {
	got := NewDefaultHandler(DefaultSSHAgentPipe, true)
	if got.SSHAgentPipe != DefaultSSHAgentPipe {
		t.Errorf("NewDefaultHandler() SSHAgentPipe = %q, want %q", got.SSHAgentPipe, DefaultSSHAgentPipe)
	}
	if !got.pageantPipe {
		t.Error("NewDefaultHandler() pageantPipe = false, want true")
	}
	if got.PageantRequestHandler == nil {
		t.Error("NewDefaultHandler() PageantRequestHandler is nil")
	}
}

func TestWithPageantRequestHandler(t *testing.T) {
	sentinel := []byte{1, 2, 3}
	handler := func(_ *Pageant, _ []byte) ([]byte, error) {
		return sentinel, nil
	}

	got := NewWithOptions(WithPageantRequestHandler(handler))
	if got.PageantRequestHandler == nil {
		t.Fatal("WithPageantRequestHandler() did not set the handler")
	}

	res, err := got.PageantRequestHandler(got, nil)
	if err != nil {
		t.Fatalf("handler returned an unexpected error: %v", err)
	}
	if string(res) != string(sentinel) {
		t.Errorf("handler returned %v, want %v", res, sentinel)
	}
}

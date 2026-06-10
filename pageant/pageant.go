package pageant

import "log"

// DefaultSSHAgentPipe is the default named pipe for the Windows OpenSSH agent.
const DefaultSSHAgentPipe = `\\.\pipe\openssh-ssh-agent`

// PageantRequestHandler handles an incoming pageant request. The request is the
// raw agent message including its 4-byte big-endian length prefix; the returned
// slice must be the complete reply, likewise including its length prefix.
type PageantRequestHandler func(p *Pageant, request []byte) ([]byte, error)

type Pageant struct {
	// SSHAgentPipe is the pipe for the windows openssh agent (e.g \\.\pipe\openssh-ssh-agent).
	// Set it before calling Run; mutating it afterwards races with the request handlers.
	SSHAgentPipe string
	pageantPipe  bool // enable pageant named pipe proxying (not the same as the windows openssh pipe)

	// PageantRequestHandler is called when an incoming pageant key request is
	// received. The result of the function is sent back to the requesting client.
	// Set it before calling Run; mutating it afterwards races with the request handlers.
	PageantRequestHandler PageantRequestHandler
}

// New creates a new pageant with explicit arguments
func New(openSSHPipe string, enablePageantPipe bool, pageantRequestHandler PageantRequestHandler) *Pageant {
	return &Pageant{
		SSHAgentPipe:          openSSHPipe,
		pageantPipe:           enablePageantPipe,
		PageantRequestHandler: pageantRequestHandler,
	}
}

// NewDefaultHandler creates a new pageant with the default handler func
func NewDefaultHandler(openSSHPipe string, enablePageantPipe bool) *Pageant {
	return New(openSSHPipe, enablePageantPipe, defaultHandlerFunc)
}

// Configure the pageant with the given options if provided, otherwise use defaults
func NewWithOptions(opts ...Option) *Pageant {
	// initialize with defaults
	p := New(DefaultSSHAgentPipe, true, defaultHandlerFunc)

	// apply options
	for _, applyTo := range opts {
		err := applyTo(p)
		if err != nil {
			log.Printf("Error applying option: %v\n", err)
		}
	}
	return p
}

type Option func(p *Pageant) error

func WithSSHPipe(sshPipe string) Option {
	return func(p *Pageant) error {
		p.SSHAgentPipe = sshPipe
		return nil
	}
}

func WithPageantPipe(pageantPipe bool) Option {
	return func(p *Pageant) error {
		p.pageantPipe = pageantPipe
		return nil
	}
}

func WithPageantRequestHandler(handler PageantRequestHandler) Option {
	return func(p *Pageant) error {
		p.PageantRequestHandler = handler
		return nil
	}
}

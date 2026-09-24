//go:build !windows

package pageant

import (
	"errors"
)

func defaultHandlerFunc(_ *Pageant, _ []byte) ([]byte, error) {
	return nil, errors.New("not supported")
}

type runtimeState struct{}

func (p *Pageant) Run() error        { return errors.New("winssh-pageant is only supported on Windows") }
func ExitRunning() error             { return errors.New("Windows required") }
func ShowRunningKeys() (bool, error) { return false, errors.New("Windows required") }
func ShowError(err error)            {}
func PrepareConsole()                {}

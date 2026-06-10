//go:build !windows

package pageant

import (
	"errors"
	"log"
)

func defaultHandlerFunc(_ *Pageant, _ []byte) ([]byte, error) {
	return nil, errors.New("not supported")
}

func (p *Pageant) Run() {
	log.Println("winssh-pageant bridge is only supported on Windows")
}

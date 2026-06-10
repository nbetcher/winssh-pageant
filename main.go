package main

import (
	"flag"

	"github.com/ndbeals/winssh-pageant/pageant"
)

func main() {
	sshPipe := flag.String("sshpipe", pageant.DefaultSSHAgentPipe, "Named pipe for Windows OpenSSH agent")
	noPageantPipe := flag.Bool("no-pageant-pipe", false,
		"Toggle pageant named pipe proxying (this is different from the windows OpenSSH pipe)")
	flag.Parse()

	p := pageant.NewDefaultHandler(*sshPipe, !*noPageantPipe)

	p.Run()
}

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/ndbeals/winssh-pageant/pageant"
)

var version = "development"

func main() {
	pageant.PrepareConsole()
	sshPipe := flag.String("sshpipe", pageant.DefaultSSHAgentPipe, "Named pipe for Windows OpenSSH agent")
	noPageantPipe := flag.Bool("no-pageant-pipe", false,
		"Toggle pageant named pipe proxying (this is different from the windows OpenSSH pipe)")
	exit := flag.Bool("exit", false, "Exit the running copy at this executable's installation path")
	showKeys := flag.Bool("show-keys", false, "Display the known public SSH keys")
	showVersion := flag.Bool("version", false, "Display the application version")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	if *exit {
		if err := pageant.ExitRunning(); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	if *showKeys {
		shown, err := pageant.ShowRunningKeys()
		if err != nil {
			pageant.ShowError(err)
			os.Exit(1)
		}
		if shown {
			return
		}
	}

	p := pageant.NewDefaultHandler(*sshPipe, !*noPageantPipe)

	p.ShowKeysOnStart = *showKeys
	if err := p.Run(); err != nil {
		log.Print(err)
		pageant.ShowError(err)
		os.Exit(1)
	}
}

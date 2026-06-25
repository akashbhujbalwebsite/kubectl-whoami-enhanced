package main

import (
	"os"

	"github.com/akash/kubectl-whoami-enhanced/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

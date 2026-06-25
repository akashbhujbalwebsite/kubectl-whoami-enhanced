package main

import (
	"os"

	"github.com/akash/kubectl-whoami-enhanced/cmd"

	// Enable cloud provider auth plugins (OIDC, AWS, GCP, Azure)
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

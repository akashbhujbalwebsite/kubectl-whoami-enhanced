package cmd

import (
	"github.com/akash/kubectl-whoami-enhanced/pkg/whoami"
	"github.com/spf13/cobra"
)

var namespace     string
var allNamespaces bool
var outputJSON    bool

var rootCmd = &cobra.Command{
	Use:   "kubectl-whoami",
	Short: "Show who you are and what you can do in the cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		return whoami.Run(namespace, allNamespaces, outputJSON)
	},
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "default", "Namespace to check permissions in")
	rootCmd.Flags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Check permissions across all namespaces")
	rootCmd.Flags().BoolVar(&outputJSON, "output-json", false, "Output in JSON format")
}

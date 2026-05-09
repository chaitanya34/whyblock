package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "whyblock",
	Short: "Diagnose AWS EC2 network connectivity issues",
	Long: `whyblock checks every network layer between the internet and your
EC2 instance and tells you exactly where traffic is being blocked.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

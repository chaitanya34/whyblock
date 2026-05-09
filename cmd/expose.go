package cmd

import "github.com/spf13/cobra"

var exposeCmd = &cobra.Command{
	Use:   "expose",
	Short: "Show all ports reachable from the internet on an EC2 instance",
	RunE:  runExpose,
}

func init() {
	rootCmd.AddCommand(exposeCmd)

	exposeCmd.Flags().String("instance", "", "EC2 instance ID (required)")
	exposeCmd.Flags().String("from", "0.0.0.0/0", "Source IP, CIDR, or internet")
	exposeCmd.Flags().String("output", "table", "Output format: table, json, yaml")
	exposeCmd.Flags().String("region", "", "AWS region")
	exposeCmd.Flags().String("profile", "", "AWS profile name")

	exposeCmd.MarkFlagRequired("instance")
}

func runExpose(cmd *cobra.Command, args []string) error {
	// TODO: implement
	return nil
}

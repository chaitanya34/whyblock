package cmd

import "github.com/spf13/cobra"

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check if a port is reachable on an EC2 instance",
	RunE:  runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)

	checkCmd.Flags().String("instance", "", "EC2 instance ID (required)")
	checkCmd.Flags().Int("port", 0, "Port number to check (required)")
	checkCmd.Flags().String("proto", "tcp", "Protocol: tcp or udp")
	checkCmd.Flags().String("from", "0.0.0.0/0", "Source IP, CIDR, or internet")
	checkCmd.Flags().Int("timeout", 5, "TCP probe timeout in seconds")
	checkCmd.Flags().String("output", "table", "Output format: table, json, yaml")
	checkCmd.Flags().String("region", "", "AWS region")
	checkCmd.Flags().String("profile", "", "AWS profile name")

	checkCmd.MarkFlagRequired("instance")
	checkCmd.MarkFlagRequired("port")
}

func runCheck(cmd *cobra.Command, args []string) error {
	// TODO: implement
	return nil
}

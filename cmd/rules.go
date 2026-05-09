package cmd

import "github.com/spf13/cobra"

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Dump all effective network rules for an EC2 instance",
	RunE:  runRules,
}

func init() {
	rootCmd.AddCommand(rulesCmd)

	rulesCmd.Flags().String("instance", "", "EC2 instance ID (required)")
	rulesCmd.Flags().String("output", "table", "Output format: table, json, yaml")
	rulesCmd.Flags().String("region", "", "AWS region")
	rulesCmd.Flags().String("profile", "", "AWS profile name")

	rulesCmd.MarkFlagRequired("instance")
}

func runRules(cmd *cobra.Command, args []string) error {
	// TODO: implement
	return nil
}

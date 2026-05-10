package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/chaitanya34/whyblock/internal/analyzer"
	awsclient "github.com/chaitanya34/whyblock/internal/aws"
	"github.com/chaitanya34/whyblock/internal/model"
	"github.com/chaitanya34/whyblock/internal/output"
	"github.com/chaitanya34/whyblock/internal/probe"
	"github.com/spf13/cobra"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Dump all effective network rules for an EC2 instance",
	Example: `  # Show all rules for an instance
  whyblock rules --instance i-0abc123def456

  # Use a specific profile
  whyblock rules --instance i-0abc123def456 --profile prod`,
	RunE: runRules,
}

func init() {
	rootCmd.AddCommand(rulesCmd)

	rulesCmd.Flags().String("instance", "", "EC2 instance ID (required)")
	rulesCmd.Flags().String("region", "", "AWS region (defaults to AWS config)")
	rulesCmd.Flags().String("profile", "", "AWS profile name (defaults to AWS config)")

	rulesCmd.MarkFlagRequired("instance")
}

func runRules(cmd *cobra.Command, args []string) error {
	opts, err := parseRulesOptions(cmd)
	if err != nil {
		return err
	}

	ctx := context.Background()

	client, err := awsclient.NewClient(ctx, opts.Region, opts.Profile)
	if err != nil {
		return fmt.Errorf("failed to initialize AWS client: %w", err)
	}

	// rules command does not need a prober
	// pass a no-op prober
	a := analyzer.NewAnalyzer(client, probe.NewTCPProber())

	result, err := a.Rules(ctx, opts)
	if err != nil {
		var permErr *analyzer.MissingPermissionsError
		if isPermissionsError(err, &permErr) {
			printMissingPermissions(permErr)
			os.Exit(2)
		}
		return err
	}

	output.RenderRules(os.Stdout, result)
	return nil
}

func parseRulesOptions(cmd *cobra.Command) (model.RulesOptions, error) {
	instance, _ := cmd.Flags().GetString("instance")
	region, _ := cmd.Flags().GetString("region")
	profile, _ := cmd.Flags().GetString("profile")

	return model.RulesOptions{
		InstanceID: instance,
		Region:     region,
		Profile:    profile,
	}, nil
}

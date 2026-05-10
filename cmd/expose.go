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

var exposeCmd = &cobra.Command{
	Use:   "expose",
	Short: "Show all ports reachable from the internet on an EC2 instance",
	Example: `  # Show all exposed ports
  whyblock expose --instance i-0abc123def456

  # Check exposure from a specific source
  whyblock expose --instance i-0abc123def456 --from 10.0.1.0/24`,
	RunE: runExpose,
}

func init() {
	rootCmd.AddCommand(exposeCmd)

	exposeCmd.Flags().String("instance", "", "EC2 instance ID (required)")
	exposeCmd.Flags().String("from", "0.0.0.0/0", "Source IP, CIDR, or internet")
	exposeCmd.Flags().String("region", "", "AWS region (defaults to AWS config)")
	exposeCmd.Flags().String("profile", "", "AWS profile name (defaults to AWS config)")

	exposeCmd.MarkFlagRequired("instance")
}

func runExpose(cmd *cobra.Command, args []string) error {
	opts, err := parseExposeOptions(cmd)
	if err != nil {
		return err
	}

	ctx := context.Background()

	client, err := awsclient.NewClient(ctx, opts.Region, opts.Profile)
	if err != nil {
		return fmt.Errorf("failed to initialize AWS client: %w", err)
	}

	prober := probe.NewTCPProber()
	a := analyzer.NewAnalyzer(client, prober)

	result, err := a.Expose(ctx, opts)
	if err != nil {
		var permErr *analyzer.MissingPermissionsError
		if isPermissionsError(err, &permErr) {
			printMissingPermissions(permErr)
			os.Exit(2)
		}
		return err
	}

	output.RenderExpose(os.Stdout, result)
	return nil
}

func parseExposeOptions(cmd *cobra.Command) (model.ExposeOptions, error) {
	instance, _ := cmd.Flags().GetString("instance")
	from, _ := cmd.Flags().GetString("from")
	region, _ := cmd.Flags().GetString("region")
	profile, _ := cmd.Flags().GetString("profile")

	if from == "internet" {
		from = "0.0.0.0/0"
	}

	return model.ExposeOptions{
		InstanceID: instance,
		From:       from,
		Region:     region,
		Profile:    profile,
	}, nil
}

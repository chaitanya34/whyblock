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

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Check if a port is reachable on an EC2 instance",
	Example: `  # Check if port 443 is open from the internet
  whyblock check --instance i-0abc123def456 --port 443

  # Check if a specific IP can reach port 5432
  whyblock check --instance i-0abc123def456 --port 5432 --from 10.0.1.45

  # Use a specific AWS profile and region
  whyblock check --instance i-0abc123def456 --port 443 --profile prod --region ap-south-1`,
	RunE: runCheck,
}

func init() {
	rootCmd.AddCommand(checkCmd)

	checkCmd.Flags().String("instance", "", "EC2 instance ID (required)")
	checkCmd.Flags().Int("port", 0, "Port number to check (required)")
	checkCmd.Flags().String("proto", "tcp", "Protocol: tcp or udp")
	checkCmd.Flags().String("from", "0.0.0.0/0", "Source IP, CIDR, or internet")
	checkCmd.Flags().Int("timeout", 5, "TCP probe timeout in seconds")
	checkCmd.Flags().String("region", "", "AWS region (defaults to AWS config)")
	checkCmd.Flags().String("profile", "", "AWS profile name (defaults to AWS config)")

	checkCmd.MarkFlagRequired("instance")
	checkCmd.MarkFlagRequired("port")
}

func runCheck(cmd *cobra.Command, args []string) error {
	// parse flags into options struct
	opts, err := parseCheckOptions(cmd)
	if err != nil {
		return err
	}

	ctx := context.Background()

	// build AWS client
	client, err := awsclient.NewClient(ctx, opts.Region, opts.Profile)
	if err != nil {
		return fmt.Errorf("failed to initialize AWS client: %w", err)
	}

	// build TCP prober
	prober := probe.NewTCPProber()

	// build analyzer
	a := analyzer.NewAnalyzer(client, prober)

	// run the check
	result, err := a.Check(ctx, opts)
	if err != nil {
		// handle missing permissions error specially
		// so we print a clean message instead of a raw error
		var permErr *analyzer.MissingPermissionsError
		if isPermissionsError(err, &permErr) {
			printMissingPermissions(permErr)
			os.Exit(2)
		}
		return err
	}

	// render result to stdout
	output.RenderCheck(os.Stdout, result)

	// exit code reflects the verdict so CI/CD pipelines can act on it
	os.Exit(verdictExitCode(result.Verdict))

	return nil
}

// parseCheckOptions reads and validates all flags into a CheckOptions struct.
func parseCheckOptions(cmd *cobra.Command) (model.CheckOptions, error) {
	instance, _ := cmd.Flags().GetString("instance")
	port, _ := cmd.Flags().GetInt("port")
	proto, _ := cmd.Flags().GetString("proto")
	from, _ := cmd.Flags().GetString("from")
	timeout, _ := cmd.Flags().GetInt("timeout")
	region, _ := cmd.Flags().GetString("region")
	profile, _ := cmd.Flags().GetString("profile")

	// validate port range
	if port < 1 || port > 65535 {
		return model.CheckOptions{},
			fmt.Errorf("invalid port %d — must be between 1 and 65535", port)
	}

	// validate protocol
	if proto != "tcp" && proto != "udp" {
		return model.CheckOptions{},
			fmt.Errorf("invalid protocol %q — must be tcp or udp", proto)
	}

	// validate timeout
	if timeout < 1 || timeout > 30 {
		return model.CheckOptions{},
			fmt.Errorf("invalid timeout %d — must be between 1 and 30 seconds", timeout)
	}

	// normalize "internet" alias to CIDR
	if from == "internet" {
		from = "0.0.0.0/0"
	}

	return model.CheckOptions{
		InstanceID: instance,
		Port:       port,
		Proto:      proto,
		From:       from,
		Timeout:    timeout,
		Region:     region,
		Profile:    profile,
	}, nil
}

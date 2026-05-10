package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/chaitanya34/whyblock/internal/analyzer"
	"github.com/chaitanya34/whyblock/internal/model"
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

// verdictExitCode maps a verdict to a Unix exit code.
//
//	0 = reachable
//	1 = blocked
//	3 = partial (AWS open but OS/app level issue)
func verdictExitCode(verdict model.VerdictStatus) int {
	switch verdict {
	case model.VerdictReachable:
		return 0
	case model.VerdictBlocked:
		return 1
	case model.VerdictPartial:
		return 3
	default:
		return 1
	}
}

// isPermissionsError checks if err is a MissingPermissionsError
// and populates target if so.
func isPermissionsError(err error, target **analyzer.MissingPermissionsError) bool {
	return errors.As(err, target)
}

// printMissingPermissions prints a clean IAM error message to stderr.
func printMissingPermissions(err *analyzer.MissingPermissionsError) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Missing IAM permissions:")
	fmt.Fprintln(os.Stderr)
	for _, p := range err.Permissions {
		fmt.Fprintf(os.Stderr, "    ✗  %s\n", p)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  Add these to your IAM policy and retry.")
	fmt.Fprintln(os.Stderr)
}

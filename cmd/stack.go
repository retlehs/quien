package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/stack"
	"github.com/spf13/cobra"
)

var stackCmd = &cobra.Command{
	Use:   "stack <domain>",
	Short: "Detect technology stack — CMS, frameworks, libraries (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := normalizeDomain(args[0])
		if err != nil {
			return err
		}
		result, err := retry.Do(func() (*stack.Result, error) {
			return stack.Detect(domain)
		})
		if err != nil {
			return fmt.Errorf("stack detection failed: %w", err)
		}
		return printJSON(result)
	},
}

func init() {
	rootCmd.AddCommand(stackCmd)
}

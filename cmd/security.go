package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/security"
	"github.com/spf13/cobra"
)

var securityCmd = &cobra.Command{
	Use:   "security <domain>",
	Short: "Security.txt analysis (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := normalizeDomain(args[0])
		if err != nil {
			return err
		}
		result, err := retry.Do(func() (*security.Result, error) {
			return security.Lookup(domain)
		})
		if err != nil {
			return fmt.Errorf("Security.txt analysis failed: %w", err)
		}
		return printJSON(result)
	},
}

func init() {
	rootCmd.AddCommand(securityCmd)
}

package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/httpinfo"
	"github.com/retlehs/quien/internal/retry"
	"github.com/spf13/cobra"
)

var httpCmd = &cobra.Command{
	Use:   "http <domain>",
	Short: "HTTP header and redirect lookup (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := normalizeDomain(args[0])
		if err != nil {
			return err
		}
		result, err := retry.Do(func() (*httpinfo.Result, error) {
			return httpinfo.Lookup(domain)
		})
		if err != nil {
			return fmt.Errorf("HTTP lookup failed: %w", err)
		}
		return printJSON(result)
	},
}

func init() {
	rootCmd.AddCommand(httpCmd)
}

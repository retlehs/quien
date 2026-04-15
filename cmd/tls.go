package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/tlsinfo"
	"github.com/spf13/cobra"
)

var tlsCmd = &cobra.Command{
	Use:     "tls <domain>",
	Aliases: []string{"ssl"},
	Short:   "SSL/TLS certificate lookup (JSON output)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := normalizeDomain(args[0])
		cert, err := retry.Do(func() (*tlsinfo.CertInfo, error) {
			return tlsinfo.Lookup(domain)
		})
		if err != nil {
			return fmt.Errorf("TLS lookup failed: %w", err)
		}
		return printJSON(cert)
	},
}

func init() {
	rootCmd.AddCommand(tlsCmd)
}

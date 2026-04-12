package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/mail"
	"github.com/retlehs/quien/internal/retry"
	"github.com/spf13/cobra"
)

var mailCmd = &cobra.Command{
	Use:   "mail <domain>",
	Short: "Mail configuration lookup — MX, SPF, DMARC, DKIM, BIMI (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := normalizeDomain(args[0])
		records, err := retry.Do(func() (*mail.Records, error) {
			return mail.Lookup(domain)
		})
		if err != nil {
			return fmt.Errorf("mail lookup failed: %w", err)
		}
		return printJSON(records)
	},
}

func init() {
	rootCmd.AddCommand(mailCmd)
}

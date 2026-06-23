package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/dnsutil"
	"github.com/retlehs/quien/internal/mail"
	"github.com/retlehs/quien/internal/retry"
	"github.com/spf13/cobra"
)

var mailResolveFlag bool

var mailCmd = &cobra.Command{
	Use:   "mail <domain>",
	Short: "Mail configuration lookup — MX, SPF, DMARC, DKIM, BIMI (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := normalizeDomain(args[0])
		if err != nil {
			return err
		}
		records, err := retry.Do(func() (*mail.Records, error) {
			return mail.Lookup(domain)
		})
		if err != nil {
			return fmt.Errorf("mail lookup failed: %w", err)
		}
		if mailResolveFlag {
			records.MXResolved = dnsutil.ResolveHosts(mxHosts(records.MX))
		}
		return printJSON(records)
	},
}

// mxHosts extracts the hostnames from a slice of MX records.
func mxHosts(mx []mail.MXRecord) []string {
	hosts := make([]string, len(mx))
	for i, r := range mx {
		hosts[i] = r.Host
	}
	return hosts
}

func init() {
	mailCmd.Flags().BoolVar(&mailResolveFlag, "resolve", false, "resolve MX hostnames to IP addresses and reverse DNS")
	rootCmd.AddCommand(mailCmd)
}

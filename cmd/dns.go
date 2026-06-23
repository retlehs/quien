package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/retlehs/quien/internal/dns"
	"github.com/retlehs/quien/internal/dnsutil"
	"github.com/retlehs/quien/internal/resolver"
	"github.com/retlehs/quien/internal/retry"
	"github.com/spf13/cobra"
)

var dnsResolveFlag bool

var dnsCmd = &cobra.Command{
	Use:   "dns <domain>",
	Short: "DNS record lookup (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain, err := normalizeDomain(args[0])
		if err != nil {
			return err
		}
		records, err := retry.Do(func() (*dns.Records, error) {
			return dns.Lookup(domain)
		})
		if err != nil {
			return fmt.Errorf("DNS lookup failed: %w", err)
		}
		if dnsResolveFlag {
			records.NSResolved = dnsutil.ResolveHosts(records.NS)
		}
		return printJSON(records)
	},
}

func init() {
	dnsCmd.Flags().BoolVar(&dnsResolveFlag, "resolve", false, "resolve NS hostnames to IP addresses and reverse DNS")
	rootCmd.AddCommand(dnsCmd)
}

func normalizeDomain(s string) (string, error) {
	return resolver.NormalizeDomain(s)
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

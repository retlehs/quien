package cmd

import (
	"fmt"
	"net"

	"github.com/retlehs/quien/internal/resolver"
	"github.com/spf13/cobra"
)

var whoisCmd = &cobra.Command{
	Use:   "whois <domain or IP>",
	Short: "WHOIS/RDAP registration lookup (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := normalizeDomain(args[0])
		if net.ParseIP(input) != nil {
			info, err := resolver.LookupIP(input)
			if err != nil {
				return fmt.Errorf("IP lookup failed: %w", err)
			}
			return printJSON(info)
		}
		info, err := resolver.Lookup(input)
		if err != nil {
			return fmt.Errorf("WHOIS lookup failed: %w", err)
		}
		return printJSON(info)
	},
}

func init() {
	rootCmd.AddCommand(whoisCmd)
}

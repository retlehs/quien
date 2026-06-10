package cmd

import (
	"fmt"
	"net"

	"github.com/retlehs/quien/internal/resolver"
)

func init() {
	register(&command{
		name:  "whois",
		short: "WHOIS/RDAP registration lookup (JSON output)",
		run: func(args []string) error {
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
	})
}

package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/retlehs/quien/internal/dns"
	"github.com/retlehs/quien/internal/retry"
)

func init() {
	register(&command{
		name:  "dns",
		short: "DNS record lookup (JSON output)",
		run: func(args []string) error {
			domain := normalizeDomain(args[0])
			records, err := retry.Do(func() (*dns.Records, error) {
				return dns.Lookup(domain)
			})
			if err != nil {
				return fmt.Errorf("DNS lookup failed: %w", err)
			}
			return printJSON(records)
		},
	})
}

func normalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

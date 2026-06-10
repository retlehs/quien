package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/httpinfo"
	"github.com/retlehs/quien/internal/retry"
)

func init() {
	register(&command{
		name:  "http",
		short: "HTTP header and redirect lookup (JSON output)",
		run: func(args []string) error {
			domain := normalizeDomain(args[0])
			result, err := retry.Do(func() (*httpinfo.Result, error) {
				return httpinfo.Lookup(domain)
			})
			if err != nil {
				return fmt.Errorf("HTTP lookup failed: %w", err)
			}
			return printJSON(result)
		},
	})
}

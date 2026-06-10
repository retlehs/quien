package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/seo"
)

func init() {
	register(&command{
		name:  "seo",
		short: "SEO and Core Web Vitals analysis (JSON output)",
		run: func(args []string) error {
			domain := normalizeDomain(args[0])
			result, err := retry.Do(func() (*seo.Result, error) {
				return seo.Analyze(domain)
			})
			if err != nil {
				return fmt.Errorf("SEO analysis failed: %w", err)
			}
			return printJSON(result)
		},
	})
}

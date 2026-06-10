package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/stack"
)

func init() {
	register(&command{
		name:  "stack",
		short: "Detect technology stack — CMS, frameworks, libraries (JSON output)",
		run: func(args []string) error {
			domain := normalizeDomain(args[0])
			result, err := retry.Do(func() (*stack.Result, error) {
				return stack.Detect(domain)
			})
			if err != nil {
				return fmt.Errorf("stack detection failed: %w", err)
			}
			return printJSON(result)
		},
	})
}

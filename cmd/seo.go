package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/seo"
	"github.com/spf13/cobra"
)

var seoCmd = &cobra.Command{
	Use:   "seo <domain>",
	Short: "SEO and Core Web Vitals analysis (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := normalizeDomain(args[0])
		result, err := retry.Do(func() (*seo.Result, error) {
			return seo.Analyze(domain)
		})
		if err != nil {
			return fmt.Errorf("SEO analysis failed: %w", err)
		}
		return printJSON(result)
	},
}

func init() {
	rootCmd.AddCommand(seoCmd)
}

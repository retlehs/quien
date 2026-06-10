package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/mail"
	"github.com/retlehs/quien/internal/retry"
)

func init() {
	register(&command{
		name:  "mail",
		short: "Mail configuration lookup — MX, SPF, DMARC, DKIM, BIMI (JSON output)",
		run: func(args []string) error {
			domain := normalizeDomain(args[0])
			records, err := retry.Do(func() (*mail.Records, error) {
				return mail.Lookup(domain)
			})
			if err != nil {
				return fmt.Errorf("mail lookup failed: %w", err)
			}
			return printJSON(records)
		},
	})
}

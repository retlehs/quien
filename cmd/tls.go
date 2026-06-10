package cmd

import (
	"fmt"

	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/tlsinfo"
)

func init() {
	register(&command{
		name:    "tls",
		aliases: []string{"ssl"},
		short:   "SSL/TLS certificate lookup (JSON output)",
		run: func(args []string) error {
			domain := normalizeDomain(args[0])
			cert, err := retry.Do(func() (*tlsinfo.CertInfo, error) {
				return tlsinfo.Lookup(domain)
			})
			if err != nil {
				return fmt.Errorf("TLS lookup failed: %w", err)
			}
			return printJSON(cert)
		},
	})
}

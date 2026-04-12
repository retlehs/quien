package cmd

import (
	"fmt"
	"net"

	"github.com/retlehs/quien/internal/dns"
	"github.com/retlehs/quien/internal/httpinfo"
	"github.com/retlehs/quien/internal/mail"
	"github.com/retlehs/quien/internal/resolver"
	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/seo"
	"github.com/retlehs/quien/internal/stack"
	"github.com/retlehs/quien/internal/tlsinfo"
	"github.com/spf13/cobra"
)

type allResult struct {
	WHOIS *any              `json:"whois,omitempty"`
	DNS   *dns.Records      `json:"dns,omitempty"`
	Mail  *mail.Records     `json:"mail,omitempty"`
	TLS   *tlsinfo.CertInfo `json:"tls,omitempty"`
	HTTP  *httpinfo.Result  `json:"http,omitempty"`
	Stack *stack.Result     `json:"stack,omitempty"`
	SEO   *seo.Result       `json:"seo,omitempty"`
}

var allCmd = &cobra.Command{
	Use:   "all <domain or IP>",
	Short: "Run all lookups combined (JSON output)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		input := normalizeDomain(args[0])
		result := allResult{}

		isIP := net.ParseIP(input) != nil

		if isIP {
			info, err := resolver.LookupIP(input)
			if err != nil {
				return fmt.Errorf("IP lookup failed: %w", err)
			}
			var w any = info
			result.WHOIS = &w
			return printJSON(result)
		}

		// WHOIS
		if info, err := resolver.Lookup(input); err == nil {
			var w any = info
			result.WHOIS = &w
		}

		// DNS
		if records, err := retry.Do(func() (*dns.Records, error) { return dns.Lookup(input) }); err == nil {
			result.DNS = records
		}

		// Mail
		if records, err := retry.Do(func() (*mail.Records, error) { return mail.Lookup(input) }); err == nil {
			result.Mail = records
		}

		// TLS
		if cert, err := retry.Do(func() (*tlsinfo.CertInfo, error) { return tlsinfo.Lookup(input) }); err == nil {
			result.TLS = cert
		}

		// HTTP
		if info, err := retry.Do(func() (*httpinfo.Result, error) { return httpinfo.Lookup(input) }); err == nil {
			result.HTTP = info
		}

		// Stack + SEO (shared page fetch)
		if page, err := retry.Do(func() (*stack.PageData, error) { return stack.FetchPage(input) }); err == nil {
			result.Stack = stack.DetectFromPage(page.Headers, page.Body, input)
			result.SEO = seo.AnalyzeWithPage(page, input)
		}

		return printJSON(result)
	},
}

func init() {
	rootCmd.AddCommand(allCmd)
}

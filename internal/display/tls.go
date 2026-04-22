package display

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/retlehs/quien/internal/tlsinfo"
)

// RenderTLS returns a lipgloss-styled string for TLS certificate info.
func RenderTLS(cert *tlsinfo.CertInfo) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle("SSL/TLS Certificate"))
	b.WriteString("\n\n")

	b.WriteString(row("Subject", cert.Subject))
	b.WriteString(row("Issuer", cert.Issuer))
	b.WriteString(row("Algorithm", cert.SigAlgo))

	b.WriteString("\n")
	b.WriteString(section("Validity"))
	b.WriteString(dateRow("Not Before", cert.NotBefore))
	b.WriteString(dateRow("Not After", cert.NotAfter))

	// Expiry status
	if cert.IsExpired {
		status := lipgloss.NewStyle().Foreground(red).Bold(true).Render("EXPIRED")
		b.WriteString(row("Status", status))
	} else if cert.DaysLeft <= 30 {
		status := lipgloss.NewStyle().Foreground(yellow).Render(fmt.Sprintf("%d days remaining", cert.DaysLeft))
		b.WriteString(row("Status", status))
	} else {
		status := lipgloss.NewStyle().Foreground(green).Render(fmt.Sprintf("%d days remaining", cert.DaysLeft))
		b.WriteString(row("Status", status))
	}

	if len(cert.SANs) > 0 {
		b.WriteString("\n")
		b.WriteString(section("Subject Alt Names"))
		for _, san := range cert.SANs {
			b.WriteString(row("", nsStyle.Render(san)))
		}
	}

	if len(cert.KeyUsage) > 0 {
		b.WriteString("\n")
		b.WriteString(row("Key Usage", strings.Join(cert.KeyUsage, ", ")))
	}

	return b.String()
}

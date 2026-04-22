package display

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/retlehs/quien/internal/mail"
)

var (
	foundStyle    = lipgloss.NewStyle().Foreground(green)
	notFoundStyle = lipgloss.NewStyle().Foreground(red)
	recordStyle   = lipgloss.NewStyle().Foreground(muted)
)

// RenderMail returns a lipgloss-styled string for email-related DNS records.
// mxResolutions (optional) adds expanded IP/rDNS info under each MX host.
func RenderMail(records *mail.Records, mxResolutions []mail.MXResolution) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle("Mail Configuration"))
	b.WriteString("\n\n")

	resolutionByHost := map[string]mail.MXResolution{}
	for _, r := range mxResolutions {
		resolutionByHost[r.Host] = r
	}

	// MX Records
	b.WriteString(section("MX Records"))
	if len(records.MX) > 0 {
		for _, mx := range records.MX {
			pri := dimStyle.Render(fmt.Sprintf("(%d)", mx.Priority))
			b.WriteString(row("", nsStyle.Render(mx.Host)+" "+pri))
			if res, ok := resolutionByHost[mx.Host]; ok {
				if res.Err != "" {
					b.WriteString(row("", dimStyle.Render("  "+notFoundStyle.Render(res.Err))))
				} else {
					for _, ip := range res.IPs {
						line := recordStyle.Render("  " + ip.IP)
						if ip.PTR != "" {
							line += "  " + dimStyle.Render("("+ip.PTR+")")
						}
						b.WriteString(row("", line))
					}
				}
			}
		}
	} else {
		b.WriteString(row("", notFoundStyle.Render("No MX records found")))
	}

	// SPF
	b.WriteString("\n")
	b.WriteString(section("SPF"))
	if records.SPF != "" {
		b.WriteString(row("Status", foundStyle.Render("found")))
		// Word-wrap long SPF records
		b.WriteString(wrapRecord(records.SPF))
	} else {
		b.WriteString(row("Status", notFoundStyle.Render("not found")))
	}

	// DMARC
	b.WriteString("\n")
	b.WriteString(section("DMARC"))
	if records.DMARC != "" {
		b.WriteString(row("Status", foundStyle.Render("found")))
		b.WriteString(wrapRecord(records.DMARC))
	} else {
		b.WriteString(row("Status", notFoundStyle.Render("not found")))
	}

	// DKIM
	b.WriteString("\n")
	b.WriteString(section("DKIM"))
	if len(records.DKIM) > 0 {
		for _, dk := range records.DKIM {
			sel := nsStyle.Render(dk.Selector)
			b.WriteString(row("Selector", sel))
			b.WriteString(wrapRecord(dk.Value))
		}
	} else {
		b.WriteString(row("Status", dimStyle.Render("no records found (checked common selectors)")))
	}

	// BIMI
	b.WriteString("\n")
	b.WriteString(section("BIMI"))
	if records.BIMI != nil {
		b.WriteString(row("Status", foundStyle.Render("found")))
		if records.BIMI.LogoURL != "" {
			b.WriteString(row("Logo", records.BIMI.LogoURL))
		}
		if records.BIMI.VMCURL != "" {
			b.WriteString(row("VMC", records.BIMI.VMCURL))
			renderVMC(&b, records.BIMI.VMC)
		} else {
			b.WriteString(row("VMC", dimStyle.Render("not advertised")))
		}
	} else {
		b.WriteString(row("Status", notFoundStyle.Render("not found")))
	}

	return b.String()
}

func renderVMC(b *strings.Builder, vmc *mail.VMCInfo) {
	if vmc == nil {
		return
	}
	if vmc.Error != "" {
		b.WriteString(row("Cert", notFoundStyle.Render(vmc.Error)))
		return
	}

	var status string
	switch {
	case vmc.IsExpired:
		status = notFoundStyle.Render("expired")
	case vmc.ChainValid && vmc.HasBIMIEKU:
		status = foundStyle.Render(fmt.Sprintf("valid (%d days left)", vmc.DaysLeft))
	case vmc.ChainValid && !vmc.HasBIMIEKU:
		status = notFoundStyle.Render("chain ok, missing BIMI EKU")
	default:
		status = notFoundStyle.Render("invalid")
	}
	b.WriteString(row("Cert", status))
	if vmc.Subject != "" {
		b.WriteString(row("Subject", vmc.Subject))
	}
	if vmc.Issuer != "" {
		b.WriteString(row("Issuer", vmc.Issuer))
	}
}

func wrapRecord(s string) string {
	maxWidth := valueWidth()
	if maxWidth < 10 {
		maxWidth = 10
	}
	indent := strings.Repeat(" ", labelWidth+gutter)
	lines := wrapText(s, maxWidth)
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(indent + recordStyle.Render(line) + "\n")
	}
	return b.String()
}

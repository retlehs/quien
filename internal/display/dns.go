package display

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/retlehs/quien/internal/dns"
)

// RenderDNS returns a lipgloss-styled string for DNS records.
func RenderDNS(records *dns.Records) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle("DNS Records"))
	b.WriteString("\n\n")

	hasRecords := false

	if len(records.A) > 0 {
		hasRecords = true
		b.WriteString(section("A"))
		for _, a := range records.A {
			b.WriteString(row("", nsStyle.Render(a)))
		}
	}

	if len(records.AAAA) > 0 {
		hasRecords = true
		if len(records.A) > 0 {
			b.WriteString("\n")
		}
		b.WriteString(section("AAAA"))
		for _, aaaa := range records.AAAA {
			b.WriteString(row("", nsStyle.Render(aaaa)))
		}
	}

	if len(records.CNAME) > 0 {
		hasRecords = true
		b.WriteString("\n")
		b.WriteString(section("CNAME"))
		for _, cname := range records.CNAME {
			b.WriteString(row("", nsStyle.Render(cname)))
		}
	}

	if len(records.MX) > 0 {
		hasRecords = true
		b.WriteString("\n")
		b.WriteString(section("MX"))
		for _, mx := range records.MX {
			pri := dimStyle.Render(fmt.Sprintf("(%d)", mx.Priority))
			b.WriteString(row("", nsStyle.Render(mx.Host)+" "+pri))
		}
	}

	if len(records.NS) > 0 {
		hasRecords = true
		b.WriteString("\n")
		b.WriteString(section("NS"))
		for _, ns := range records.NS {
			b.WriteString(row("", nsStyle.Render(ns)))
		}
	}

	if len(records.TXT) > 0 {
		hasRecords = true
		b.WriteString("\n")
		b.WriteString(section("TXT"))
		for _, txt := range records.TXT {
			// Truncate long TXT records for display
			display := txt
			if len(display) > 60 {
				display = display[:57] + "..."
			}
			b.WriteString(row("", txtStyle.Render(display)))
		}
	}

	if len(records.PTR) > 0 {
		hasRecords = true
		b.WriteString("\n")
		b.WriteString(section("PTR"))
		for _, ptr := range records.PTR {
			b.WriteString(row(ptr.IP, nsStyle.Render(ptr.Hostname)))
		}
	}

	if records.SOA != nil {
		hasRecords = true
		b.WriteString("\n")
		b.WriteString(section("SOA"))
		b.WriteString(row("Primary NS", records.SOA.PrimaryNS))
		b.WriteString(row("Admin", records.SOA.AdminEmail))
		b.WriteString(row("Serial", fmt.Sprintf("%d", records.SOA.Serial)))
	}

	// DNSSEC status
	b.WriteString("\n")
	if records.DNSSEC {
		dnssecVal := lipgloss.NewStyle().Foreground(green).Render("signed")
		b.WriteString(row("DNSSEC", dnssecVal))
	} else {
		dnssecVal := dimStyle.Render("unsigned")
		b.WriteString(row("DNSSEC", dnssecVal))
	}

	if !hasRecords {
		b.WriteString(dimStyle.Render("  No records found"))
		b.WriteString("\n")
	}

	return b.String()
}

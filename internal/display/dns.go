package display

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/retlehs/quien/internal/dns"
	"github.com/retlehs/quien/internal/dnsutil"
)

// RenderDNS returns a lipgloss-styled string for DNS records. nsResolutions
// (optional) adds expanded IP/rDNS info under each NS host.
func RenderDNS(records *dns.Records, nsResolutions []dnsutil.HostResolution) string {
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

	if len(records.HTTPS) > 0 {
		hasRecords = true
		b.WriteString("\n")
		b.WriteString(section("HTTPS"))
		for _, h := range records.HTTPS {
			b.WriteString(renderHTTPSRecord(h))
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
		resolutionByHost := map[string]dnsutil.HostResolution{}
		for _, r := range nsResolutions {
			resolutionByHost[r.Host] = r
		}
		for _, ns := range records.NS {
			b.WriteString(row("", nsStyle.Render(ns)))
			if res, ok := resolutionByHost[ns]; ok {
				if res.Err != "" {
					b.WriteString(row("", dimStyle.Render("  "+notFoundStyle.Render(res.Err))))
				} else {
					for _, ip := range res.IPs {
						line := recordStyle.Render("  " + ip.IP)
						if len(ip.PTRs) > 0 {
							line += "  " + dimStyle.Render("("+strings.Join(ip.PTRs, ", ")+")")
						}
						b.WriteString(row("", line))
					}
				}
			}
		}
	}

	if len(records.TXT) > 0 {
		hasRecords = true
		b.WriteString("\n")
		b.WriteString(section("TXT"))
		for i, txt := range records.TXT {
			// Truncate long TXT records for display
			display := txt
			if len(display) > 60 {
				display = display[:57] + "..."
			}
			// Alternate shades so adjacent records are easy to tell apart.
			style := txtStyle
			if i%2 == 1 {
				style = txtStyleAlt
			}
			b.WriteString(row("", style.Render(display)))
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

// renderHTTPSRecord renders a single HTTPS (SVCB) record. Priority 0 is alias
// mode and only carries a target; otherwise the SvcParams are listed. A target
// of "." (the owner name itself) is the common case and shown without a header.
func renderHTTPSRecord(h dns.HTTPSRecord) string {
	var b strings.Builder

	target := h.Target
	if target == "." {
		target = ""
	}

	if h.Priority == 0 {
		alias := dimStyle.Render("alias → ")
		if target == "" {
			return row("", alias+dimStyle.Render("(self)"))
		}
		return row("", alias+nsStyle.Render(target))
	}

	// Service mode: always emit an identity row so priority is visible and
	// multiple records stay visually separated, even for the common "." target.
	pri := dimStyle.Render(fmt.Sprintf("(%d)", h.Priority))
	if target == "" {
		b.WriteString(row("", dimStyle.Render("(self)")+" "+pri))
	} else {
		b.WriteString(row("", nsStyle.Render(target)+" "+pri))
	}

	if len(h.ALPN) > 0 {
		b.WriteString(row("alpn", strings.Join(h.ALPN, ", ")))
	}
	if h.Port != 0 {
		b.WriteString(row("port", fmt.Sprintf("%d", h.Port)))
	}
	for _, ip := range h.IPv4Hint {
		b.WriteString(row("ipv4hint", nsStyle.Render(ip)))
	}
	for _, ip := range h.IPv6Hint {
		b.WriteString(row("ipv6hint", nsStyle.Render(ip)))
	}
	if h.ECHConfig != "" {
		b.WriteString(row("ech", lipgloss.NewStyle().Foreground(green).Render("present")))
	}
	for _, p := range h.Params {
		b.WriteString(row("", dimStyle.Render(p)))
	}

	return b.String()
}

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

// SPFExpandAll signals "expand every layer" to RenderMail.
const SPFExpandAll = -1

// RenderMail returns a lipgloss-styled string for email-related DNS records.
// mxResolutions (optional) adds expanded IP/rDNS info under each MX host.
// spfDepth controls how many layers of include/redirect to render in the SPF
// tree: 0 = top-level terms only, N = N nested layers, SPFExpandAll = full.
func RenderMail(records *mail.Records, mxResolutions []mail.MXResolution, spfDepth int) string {
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
	renderSPF(&b, records.SPF, records.SPFAnalysis, spfDepth)

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

var (
	spfOkStyle    = lipgloss.NewStyle().Foreground(green)
	spfWarnStyle  = lipgloss.NewStyle().Foreground(yellow)
	spfErrorStyle = lipgloss.NewStyle().Foreground(red)
)

func renderSPF(b *strings.Builder, raw string, a *mail.SPFAnalysis, depth int) {
	if raw == "" && (a == nil || len(a.Records) == 0) {
		b.WriteString(row("Status", notFoundStyle.Render("not found")))
		if a != nil {
			for _, e := range a.Errors {
				b.WriteString(row("Error", notFoundStyle.Render(e)))
			}
		}
		return
	}

	b.WriteString(row("Status", foundStyle.Render("found")))

	if a != nil {
		b.WriteString(row("Lookups", spfLookupBadge(a)))
		if a.VoidCount > 0 {
			b.WriteString(row("Inc voids", spfVoidBadge(a)))
		}
		if a.Multiple {
			b.WriteString(row("Warning", notFoundStyle.Render(fmt.Sprintf("multiple SPF records (%d) — PermError", len(a.Records)))))
		}
		for _, e := range a.Errors {
			b.WriteString(row("Error", notFoundStyle.Render(e)))
		}
	}

	if raw != "" {
		b.WriteString(wrapRecord(raw))
	}

	if a != nil && a.Root != nil {
		renderSPFTree(b, a.Root, 0, depth)
	}
}

func spfLookupBadge(a *mail.SPFAnalysis) string {
	text := fmt.Sprintf("%d / %d", a.LookupCount, a.LookupLimit)
	switch {
	case a.OverLimit:
		return spfErrorStyle.Render(text + "  PermError")
	case a.LookupCount >= 8:
		return spfWarnStyle.Render(text)
	default:
		return spfOkStyle.Render(text)
	}
}

func spfVoidBadge(a *mail.SPFAnalysis) string {
	text := fmt.Sprintf("%d / %d", a.VoidCount, a.VoidLimit)
	if a.OverVoidLimit {
		return spfErrorStyle.Render(text + "  over limit")
	}
	return spfWarnStyle.Render(text)
}

// renderSPFTree writes the children of node, indented by depth. maxDepth
// caps how many levels of include/redirect to descend into.
// SPFExpandAll (-1) means unlimited.
func renderSPFTree(b *strings.Builder, node *mail.SPFNode, depth int, maxDepth int) {
	if node == nil {
		return
	}
	for _, child := range node.Children {
		writeSPFNode(b, child, depth)
		if (child.Mechanism == "include" || child.Mechanism == "redirect") &&
			len(child.Children) > 0 &&
			(maxDepth == SPFExpandAll || depth < maxDepth) {
			renderSPFTree(b, child, depth+1, maxDepth)
		}
	}
}

func writeSPFNode(b *strings.Builder, n *mail.SPFNode, depth int) {
	indent := strings.Repeat("  ", depth+1)
	prefix := indent + dimStyle.Render("→ ")

	term := n.Qualifier + n.Mechanism
	if n.Target != "" {
		switch {
		case strings.HasPrefix(n.Target, "/"):
			term += n.Target
		case n.Mechanism == "redirect" || n.Mechanism == "exp":
			term = n.Mechanism + "=" + n.Target
		default:
			term += ":" + n.Target
		}
	}

	var styled string
	switch {
	case n.CountsLookup:
		styled = nsStyle.Render(term)
	default:
		styled = recordStyle.Render(term)
	}

	annotations := []string{}
	switch {
	case n.Ignored:
		annotations = append(annotations, dimStyle.Render("ignored — after all"))
	case n.Error != "":
		annotations = append(annotations, spfErrorStyle.Render("error: "+n.Error))
	case n.Void:
		annotations = append(annotations, spfWarnStyle.Render("void — no SPF record"))
	case n.Unresolved:
		annotations = append(annotations, dimStyle.Render("macro — not resolved"))
	}

	line := prefix + styled
	if len(annotations) > 0 {
		line += "  " + dimStyle.Render("(") + strings.Join(annotations, dimStyle.Render(", ")) + dimStyle.Render(")")
	}
	b.WriteString(row("", line))
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

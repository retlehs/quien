package display

import (
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/retlehs/quien/internal/httpinfo"
)

var (
	headerNameStyle = lipgloss.NewStyle().
			Foreground(accent)

	headerValStyle = lipgloss.NewStyle().
			Foreground(white)

	redirectArrowStyle = lipgloss.NewStyle().
				Foreground(dim)

	redirectURLStyle = lipgloss.NewStyle().
				Foreground(muted)

	statusOKStyle = lipgloss.NewStyle().
			Foreground(green).
			Bold(true)

	statusWarnStyle = lipgloss.NewStyle().
			Foreground(yellow).
			Bold(true)

	statusErrStyle = lipgloss.NewStyle().
			Foreground(red).
			Bold(true)
)

// RenderHTTP returns a lipgloss-styled string for HTTP header info.
func RenderHTTP(result *httpinfo.Result) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle("HTTP Headers"))
	b.WriteString("\n\n")

	// Redirect chain (if there were redirects)
	if len(result.Redirects) > 1 {
		b.WriteString(section("Redirect Chain"))
		for i, url := range result.Redirects {
			if i < len(result.Redirects)-1 {
				b.WriteString(labelStyle.Render("") + "  " + redirectURLStyle.Render(url) + "\n")
				b.WriteString(labelStyle.Render("") + "  " + redirectArrowStyle.Render("↓") + "\n")
			}
		}
		b.WriteString(labelStyle.Render("") + "  " + nsStyle.Render(result.FinalURL) + "\n")
		b.WriteString("\n")
	}

	// Status & URL
	b.WriteString(section("Response"))
	b.WriteString(row("URL", result.FinalURL))

	statusStyle := statusOKStyle
	if result.StatusCode >= 400 {
		statusStyle = statusErrStyle
	} else if result.StatusCode >= 300 {
		statusStyle = statusWarnStyle
	}
	b.WriteString(row("Status", statusStyle.Render(result.StatusText)))

	if result.ServerSoftware != "" {
		b.WriteString(row("Server", result.ServerSoftware))
	}

	// TLS info
	if result.TLSVersion != "" {
		b.WriteString(row("TLS", result.TLSVersion))
	}

	// Headers
	b.WriteString("\n")
	b.WriteString(section("Headers"))

	maxName := valueWidth()
	for _, h := range result.Headers {
		name := headerNameStyle.Render(h.Name)
		val := h.Value

		// Wrap long values
		availWidth := maxName - len(h.Name) - 2
		if availWidth < 20 {
			availWidth = 20
		}

		if len(val) <= availWidth {
			fmt.Fprintf(&b, "  %s  %s\n", name, headerValStyle.Render(val))
		} else {
			lines := wrapText(val, availWidth)
			indent := strings.Repeat(" ", len(h.Name)+4)
			for i, line := range lines {
				if i == 0 {
					fmt.Fprintf(&b, "  %s  %s\n", name, headerValStyle.Render(line))
				} else {
					b.WriteString(indent + headerValStyle.Render(line) + "\n")
				}
			}
		}
	}

	return b.String()
}

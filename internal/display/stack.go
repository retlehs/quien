package display

import (
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/retlehs/quien/internal/stack"
)

var (
	tagStyle = lipgloss.NewStyle().
			Foreground(ac("#FFFFFF", "#000000")).
			Background(accent).
			Padding(0, 1)

	tagGreenStyle = lipgloss.NewStyle().
			Foreground(ac("#FFFFFF", "#000000")).
			Background(green).
			Padding(0, 1)

	tagDimStyle = lipgloss.NewStyle().
			Foreground(ac("#FFFFFF", "#000000")).
			Background(dim).
			Padding(0, 1)
)

// RenderStack returns a lipgloss-styled string for stack detection results.
func RenderStack(result *stack.Result) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle("Tech Stack"))
	b.WriteString("\n\n")

	hasContent := false

	// Infrastructure
	if result.Server != "" || result.CDN != "" || result.Hosting != "" || result.PoweredBy != "" {
		b.WriteString(section("Infrastructure"))
		if result.Server != "" {
			b.WriteString(row("Server", result.Server))
		}
		if result.PoweredBy != "" {
			b.WriteString(row("Powered By", result.PoweredBy))
		}
		if result.CDN != "" {
			b.WriteString(row("CDN", result.CDN))
		}
		if result.Hosting != "" {
			b.WriteString(row("Hosting", result.Hosting))
		}
		hasContent = true
	}

	// CMS & Plugins
	if result.CMS != "" {
		if hasContent {
			b.WriteString("\n")
		}
		b.WriteString(section("CMS"))
		b.WriteString(row("", tagGreenStyle.Render(result.CMS)))
		if len(result.Plugins) > 0 {
			b.WriteString("\n")
			b.WriteString(section("Plugins"))
			tags := renderTags(result.Plugins, tagDimStyle)
			b.WriteString(labelStyle.Render("") + "  " + tags + "\n")
		}
		hasContent = true
	}

	// JS Libraries
	if len(result.JSLibs) > 0 {
		if hasContent {
			b.WriteString("\n")
		}
		b.WriteString(section("JavaScript"))
		tags := renderTags(result.JSLibs, tagStyle)
		b.WriteString(labelStyle.Render("") + "  " + tags + "\n")
		hasContent = true
	}

	// CSS Libraries
	if len(result.CSSLibs) > 0 {
		if hasContent {
			b.WriteString("\n")
		}
		b.WriteString(section("CSS"))
		tags := renderTags(result.CSSLibs, tagStyle)
		b.WriteString(labelStyle.Render("") + "  " + tags + "\n")
		hasContent = true
	}

	// External services
	if len(result.ExternalSvc) > 0 {
		if hasContent {
			b.WriteString("\n")
		}
		b.WriteString(section("External Services"))
		for _, svc := range result.ExternalSvc {
			typeLabel := dimStyle.Render("(" + svc.Type + ")")
			b.WriteString(labelStyle.Render("") + "  " + nsStyle.Render(svc.Domain) + " " + typeLabel + "\n")
		}
		hasContent = true
	}

	if !hasContent {
		b.WriteString(dimStyle.Render("  No technologies detected"))
		b.WriteString("\n")
	}

	return b.String()
}

func renderTags(items []string, style lipgloss.Style) string {
	var tags []string
	for _, item := range items {
		tags = append(tags, style.Render(item))
	}
	return strings.Join(tags, " ")
}

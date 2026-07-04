package display

import (
	"strings"

	"github.com/retlehs/quien/internal/security"
)

func RenderSecurity(result *security.Result) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle("security.txt"))
	b.WriteString("\n\n")

	if !result.Found {
		b.WriteString(dimStyle.Render("  No security.txt found"))
		b.WriteString("\n")
		return b.String()
	}

	b.WriteString(section("Location"))
	b.WriteString(row("URL", nsStyle.Render(result.URL)))

	fieldOrder := []string{
		"contact",
		"encryption",
		"acknowledgments",
		"preferred-languages",
		"canonical",
		"policy",
		"hiring",
		"signature",
	}

	hasFields := false
	for _, field := range fieldOrder {
		if values, ok := result.Fields[field]; ok && len(values) > 0 {
			if !hasFields {
				b.WriteString("\n")
				b.WriteString(section("Fields"))
				hasFields = true
			}
			label := strings.Title(strings.ReplaceAll(field, "-", " "))
			for _, v := range values {
				b.WriteString(row(label, headerValStyle.Render(v)))
			}
		}
	}

	if result.Content != "" {
		b.WriteString("\n")
		b.WriteString(section("Raw Content"))
		lines := strings.Split(result.Content, "\n")
		for _, line := range lines {
			b.WriteString(labelStyle.Render("") + "  " + dimStyle.Render(line) + "\n")
		}
	}

	return b.String()
}

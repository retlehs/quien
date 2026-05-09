package display

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"charm.land/lipgloss/v2"
	"github.com/retlehs/quien/internal/model"
)

// displayWidth is the current box width, updated dynamically.
var displayWidth = 72

const (
	labelWidth = 14
	gutter     = 2 // space between label and value
	boxPadH    = 2 // horizontal padding inside box (each side)
	boxBorderH = 1 // border char per side
)

// innerWidth returns the usable content width inside the box.
func innerWidth() int {
	return displayWidth - (boxPadH+boxBorderH)*2
}

// valueWidth returns the max width for a value column.
func valueWidth() int {
	return innerWidth() - labelWidth - gutter
}

// SetWidth updates the display width to match terminal width.
func SetWidth(w int) {
	if w < 40 {
		w = 40
	}
	displayWidth = w
}

var (
	// Colors — dark values are unchanged; light values target white/light backgrounds.
	cyan   = ac("#0969DA", "#00D7FF")
	green  = ac("#1A7F37", "#00FF87")
	red    = ac("#CF222E", "#FF5F87")
	yellow = ac("#9A6700", "#FFD700")
	dim    = ac("#57606A", "#6C6C6C")
	white  = ac("#1F2328", "#FFFFFF") // main body text
	faint  = ac("#8C959F", "#4E4E4E")

	// Secondary palette tokens used across multiple files.
	accent  = ac("#2E59A1", "#87AFFF") // nameservers, headers, DNS records
	muted   = ac("#57606A", "#A8A8A8") // TXT records, redirect URLs, mail records
	border  = ac("#D0D7DE", "#3A3A3A") // box and panel borders
	tabGray = ac("#57606A", "#A0A0A0") // inactive tab text

	// Styles
	domainStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan)

	labelStyle = lipgloss.NewStyle().
			Foreground(dim).
			Width(labelWidth).
			Align(lipgloss.Right)

	valueStyle = lipgloss.NewStyle().
			Foreground(white)

	sectionStyle = lipgloss.NewStyle().
			Foreground(yellow).
			Bold(true)

	dateStyle = lipgloss.NewStyle().
			Foreground(white)

	relativeStyle = lipgloss.NewStyle().
			Foreground(dim).
			Italic(true)

	nsStyle = lipgloss.NewStyle().
		Foreground(accent)

	txtStyle = lipgloss.NewStyle().
			Foreground(muted)

	dimStyle = lipgloss.NewStyle().
			Foreground(dim)

	dividerStyle = lipgloss.NewStyle().
			Foreground(faint)
)

func box() lipgloss.Style {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(1, boxPadH).
		Width(displayWidth)
}

func domainSectionTitle(title string) string {
	return domainStyle.Render(title)
}

// RenderWhois returns the WHOIS output as a styled string.
func RenderWhois(info model.DomainInfo) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle(info.DomainName))
	b.WriteString("\n")

	if info.Registrar != "" {
		b.WriteString(row("Registrar", info.Registrar))
	}

	if len(info.Status) > 0 {
		b.WriteString(row("Status", info.Status[0]))
		for _, s := range info.Status[1:] {
			b.WriteString(row("", s))
		}
	}

	if !info.CreatedDate.IsZero() || !info.UpdatedDate.IsZero() || !info.ExpiryDate.IsZero() {
		b.WriteString("\n")
		b.WriteString(section("Dates"))
		if !info.CreatedDate.IsZero() {
			b.WriteString(dateRow("Created", info.CreatedDate))
		}
		if !info.UpdatedDate.IsZero() {
			b.WriteString(dateRow("Updated", info.UpdatedDate))
		}
		if !info.ExpiryDate.IsZero() {
			b.WriteString(dateRow("Expires", info.ExpiryDate))
		}
	}

	if len(info.Nameservers) > 0 {
		b.WriteString("\n")
		b.WriteString(section("Nameservers"))
		for _, ns := range info.Nameservers {
			b.WriteString(labelStyle.Render("") + "  " + nsStyle.Render(strings.ToLower(ns)) + "\n")
		}
	}

	for _, contact := range info.Contacts {
		b.WriteString("\n")
		b.WriteString(renderContact(contact))
	}

	if len(info.Extensions) > 0 {
		b.WriteString("\n")
		b.WriteString(renderExtensions(info.ExtensionSection, info.Extensions))
	}

	return b.String()
}

// RenderRawWhois returns raw WHOIS content.
func RenderRawWhois(raw string) string {
	var b strings.Builder
	b.WriteString(domainSectionTitle("Raw WHOIS Response"))
	b.WriteString("\n\n")
	b.WriteString(dimStyle.Render(raw))
	return b.String()
}

// Render displays a DomainInfo in a polished layout (non-interactive).
func Render(info model.DomainInfo) {
	fmt.Println()
	fmt.Println(box().Render(RenderWhois(info)))
	fmt.Println()
}

// RenderJSON returns the domain info as formatted JSON.
func RenderJSON(info model.DomainInfo) string {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}
	return string(data)
}

func row(label, value string) string {
	l := labelStyle.Render(label)
	maxVal := valueWidth()
	if maxVal < 10 {
		maxVal = 10
	}

	// If value fits on one line, simple case
	plainLen := lipgloss.Width(value)
	if plainLen <= maxVal {
		return l + "  " + valueStyle.Render(value) + "\n"
	}

	// Word-wrap: split into lines that fit
	indent := strings.Repeat(" ", labelWidth+gutter)
	lines := wrapText(value, maxVal)
	var b strings.Builder
	for i, line := range lines {
		if i == 0 {
			b.WriteString(l + "  " + valueStyle.Render(line) + "\n")
		} else {
			b.WriteString(indent + valueStyle.Render(line) + "\n")
		}
	}
	return b.String()
}

func wrapText(s string, maxWidth int) []string {
	if maxWidth <= 0 {
		return []string{s}
	}

	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{s}
	}

	var lines []string
	current := words[0]

	for _, word := range words[1:] {
		if len(current)+1+len(word) <= maxWidth {
			current += " " + word
		} else {
			lines = append(lines, current)
			current = word
		}
	}
	lines = append(lines, current)

	// If a single "word" is longer than maxWidth, hard-break it
	var result []string
	for _, line := range lines {
		for len(line) > maxWidth {
			result = append(result, line[:maxWidth])
			line = line[maxWidth:]
		}
		result = append(result, line)
	}

	return result
}

func dateRow(label string, t time.Time) string {
	l := labelStyle.Render(label)
	d := dateStyle.Render(t.Format("2006-01-02"))
	r := relativeStyle.Render(relativeTime(t))
	return l + "  " + d + "  " + r + "\n"
}

func section(title string) string {
	label := sectionStyle.Render(title)
	lineWidth := innerWidth() - lipgloss.Width(title) - 1
	if lineWidth < 4 {
		lineWidth = 4
	}
	line := dividerStyle.Render(strings.Repeat("─", lineWidth))
	return label + " " + line + "\n"
}

func renderExtensions(title string, ext map[string]string) string {
	var b strings.Builder
	b.WriteString(section(title))
	keys := make([]string, 0, len(ext))
	for k := range ext {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString(row(k, ext[k]))
	}
	return b.String()
}

func renderContact(c model.Contact) string {
	var b strings.Builder
	title := strings.ToUpper(c.Role[:1]) + c.Role[1:]
	b.WriteString(section(title))

	if c.Name != "" {
		b.WriteString(row("Name", c.Name))
	}
	if c.Organization != "" {
		b.WriteString(row("Org", c.Organization))
	}
	if c.Email != "" {
		b.WriteString(row("Email", c.Email))
	}
	if c.Phone != "" {
		b.WriteString(row("Phone", c.Phone))
	}
	if c.Address != "" {
		b.WriteString(row("Address", c.Address))
	}
	return b.String()
}

func relativeTime(t time.Time) string {
	now := time.Now()
	diff := now.Sub(t)

	if diff < 0 {
		diff = -diff
		return formatDuration(diff) + " from now"
	}
	return formatDuration(diff) + " ago"
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)

	if days < 1 {
		return "today"
	}
	if days == 1 {
		return "1 day"
	}
	if days < 30 {
		return fmt.Sprintf("%d days", days)
	}
	if days < 365 {
		months := days / 30
		if months == 1 {
			return "1 month"
		}
		return fmt.Sprintf("%d months", months)
	}
	years := days / 365
	remainingMonths := (days % 365) / 30
	if years == 1 && remainingMonths == 0 {
		return "1 year"
	}
	if remainingMonths == 0 {
		return fmt.Sprintf("%d years", years)
	}
	if years == 1 {
		return fmt.Sprintf("1 year, %d months", remainingMonths)
	}
	return fmt.Sprintf("%d years, %d months", years, remainingMonths)
}

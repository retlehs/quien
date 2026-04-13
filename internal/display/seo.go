package display

import (
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/retlehs/quien/internal/seo"
)

var (
	warnStyle = lipgloss.NewStyle().Foreground(yellow)
)

// RenderSEO returns a lipgloss-styled string for SEO analysis results.
func RenderSEO(result *seo.Result) string {
	var b strings.Builder

	b.WriteString(domainSectionTitle("SEO & Performance"))
	b.WriteString("\n\n")

	renderIndexability(&b, &result.Indexability)
	b.WriteString("\n")
	renderOnPage(&b, &result.OnPage)
	b.WriteString("\n")
	renderSocial(&b, &result.Social)
	b.WriteString("\n")
	renderPerfHints(&b, &result.PerfHints)

	if result.CWV != nil {
		b.WriteString("\n")
		renderCWV(&b, result.CWV)
	}

	if result.Trend != nil {
		b.WriteString("\n")
		renderTrend(&b, result.Trend)
	}

	if result.CWV == nil {
		b.WriteString("\n")
		if result.CrUXKeySet {
			b.WriteString(dimStyle.Render("  No CrUX field data available for this origin"))
		} else {
			b.WriteString(dimStyle.Render("  Set QUIEN_CRUX_API_KEY for Core Web Vitals field data"))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func renderIndexability(b *strings.Builder, idx *seo.Indexability) {
	b.WriteString(section("Indexability"))

	if idx.Indexable {
		b.WriteString(row("Indexable", foundStyle.Render("yes")))
	} else {
		b.WriteString(row("Indexable", notFoundStyle.Render("no (noindex)")))
	}

	b.WriteString(row("robots.txt", statusText(idx.RobotsTxt == "found", idx.RobotsTxt)))

	if idx.RobotsMeta != "" {
		b.WriteString(row("Robots Meta", idx.RobotsMeta))
	}
	if idx.XRobotsTag != "" {
		b.WriteString(row("X-Robots-Tag", idx.XRobotsTag))
	}

	if idx.Canonical != "" {
		b.WriteString(row("Canonical", idx.Canonical))
	} else {
		b.WriteString(row("Canonical", dimStyle.Render("not set")))
	}

	if idx.SitemapFound {
		b.WriteString(row("Sitemap", foundStyle.Render("found")))
		if idx.SitemapURL != "" {
			b.WriteString(row("", dimStyle.Render(idx.SitemapURL)))
		}
	} else {
		b.WriteString(row("Sitemap", notFoundStyle.Render("not found")))
	}
}

func renderOnPage(b *strings.Builder, op *seo.OnPage) {
	b.WriteString(section("On-Page"))

	if op.Title != "" {
		quality := titleQuality(op.TitleLen)
		b.WriteString(row("Title", op.Title))
		b.WriteString(row("", quality+dimStyle.Render(fmt.Sprintf(" (%d chars)", op.TitleLen))))
	} else {
		b.WriteString(row("Title", notFoundStyle.Render("missing")))
	}

	if op.Description != "" {
		quality := descQuality(op.DescLen)
		b.WriteString(row("Description", op.Description))
		b.WriteString(row("", quality+dimStyle.Render(fmt.Sprintf(" (%d chars)", op.DescLen))))
	} else {
		b.WriteString(row("Description", notFoundStyle.Render("missing")))
	}

	if op.H1Count > 0 {
		label := foundStyle.Render(op.H1)
		if op.H1Count > 1 {
			label += " " + warnStyle.Render(fmt.Sprintf("(%d total — should be 1)", op.H1Count))
		}
		b.WriteString(row("H1", label))
	} else {
		b.WriteString(row("H1", notFoundStyle.Render("missing")))
	}

	if op.ImgNoAlt > 0 {
		b.WriteString(row("Images", notFoundStyle.Render(fmt.Sprintf("%d of %d missing alt", op.ImgNoAlt, op.ImgCount))))
	}

	if op.Lang == "" {
		b.WriteString(row("Lang", warnStyle.Render("not set")))
	}
}

func renderSocial(b *strings.Builder, s *seo.Social) {
	b.WriteString(section("Structured Data & Social"))

	hasOG := s.OGTitle != "" || s.OGImage != ""
	hasTwitter := s.TwitterCard != ""
	hasSchema := len(s.SchemaTypes) > 0

	if hasOG {
		b.WriteString(row("Open Graph", foundStyle.Render("found")))
		if s.OGTitle != "" {
			b.WriteString(row("  og:title", s.OGTitle))
		}
		if s.OGDescription != "" {
			b.WriteString(row("  og:desc", s.OGDescription))
		}
		if s.OGImage != "" {
			b.WriteString(row("  og:image", s.OGImage))
		}
		if s.OGType != "" {
			b.WriteString(row("  og:type", s.OGType))
		}
	} else {
		b.WriteString(row("Open Graph", notFoundStyle.Render("not found")))
	}

	if hasTwitter {
		b.WriteString(row("Twitter Card", foundStyle.Render(s.TwitterCard)))
		if s.TwitterSite != "" {
			b.WriteString(row("  site", s.TwitterSite))
		}
	} else {
		b.WriteString(row("Twitter Card", dimStyle.Render("not found")))
	}

	if hasSchema {
		unique := dedup(s.SchemaTypes)
		b.WriteString(row("JSON-LD", foundStyle.Render(fmt.Sprintf("%d types", len(unique)))))
		indent := labelStyle.Render("") + "  "
		maxW := valueWidth()
		var lineW int
		var line []string
		for _, item := range unique {
			tagStr := tagStyle.Render(item)
			tagW := lipgloss.Width(tagStr)
			if lineW > 0 && lineW+1+tagW > maxW {
				b.WriteString(indent + strings.Join(line, " ") + "\n")
				line = nil
				lineW = 0
			}
			line = append(line, tagStr)
			if lineW == 0 {
				lineW = tagW
			} else {
				lineW += 1 + tagW
			}
		}
		if len(line) > 0 {
			b.WriteString(indent + strings.Join(line, " ") + "\n")
		}
	} else {
		b.WriteString(row("JSON-LD", dimStyle.Render("not found")))
	}
}

func renderPerfHints(b *strings.Builder, p *seo.PerfHints) {
	b.WriteString(section("Performance Hints"))

	if p.Compressed {
		b.WriteString(row("Compression", foundStyle.Render(p.Encoding)))
	} else {
		b.WriteString(row("Compression", notFoundStyle.Render("none")))
	}

	if p.CacheControl != "" {
		b.WriteString(row("Cache-Control", p.CacheControl))
	} else {
		b.WriteString(row("Cache-Control", warnStyle.Render("not set")))
	}

	b.WriteString(row("Doc Size", formatBytes(p.DocSizeBytes)))
	b.WriteString(row("Preload", fmt.Sprintf("%d", p.PreloadCount)))
	b.WriteString(row("Preconnect", fmt.Sprintf("%d", p.PreconnectCount)))
	b.WriteString(row("Lazy Images", fmt.Sprintf("%d", p.LazyImages)))

	scripts := fmt.Sprintf("%d external, %d inline", p.ExternalScripts, p.InlineScripts)
	b.WriteString(row("Scripts", scripts))

	styles := fmt.Sprintf("%d external, %d inline", p.ExternalStyles, p.InlineStyles)
	b.WriteString(row("Styles", styles))
}

func renderCWV(b *strings.Builder, cwv *seo.CWVData) {
	scope := "origin"
	if cwv.Scope != "" {
		scope = cwv.Scope
	}
	b.WriteString(section(fmt.Sprintf("Core Web Vitals (%s)", scope)))

	if cwv.LCP != nil {
		b.WriteString(row("LCP", formatCWVMetric(cwv.LCP, "ms")))
	}
	if cwv.INP != nil {
		b.WriteString(row("INP", formatCWVMetric(cwv.INP, "ms")))
	}
	if cwv.CLS != nil {
		b.WriteString(row("CLS", formatCWVMetric(cwv.CLS, "")))
	}
	if cwv.FCP != nil {
		b.WriteString(row("FCP", formatCWVMetric(cwv.FCP, "ms")))
	}
	if cwv.TTFB != nil {
		b.WriteString(row("TTFB", formatCWVMetric(cwv.TTFB, "ms")))
	}
}

func renderTrend(b *strings.Builder, trend *seo.CWVTrend) {
	b.WriteString(section("CWV Trend"))

	weeks := len(trend.Periods)
	if weeks == 0 {
		b.WriteString(row("", dimStyle.Render("no trend data")))
		return
	}

	rangeLabel := dimStyle.Render(fmt.Sprintf("%s → %s (%d weeks)", trend.Periods[0], trend.Periods[weeks-1], weeks))
	b.WriteString(row("Period", rangeLabel))

	if len(trend.LCP) > 0 {
		b.WriteString(row("LCP", sparkline(trend.LCP)+"  "+dimStyle.Render("ms")))
	}
	if len(trend.INP) > 0 {
		b.WriteString(row("INP", sparkline(trend.INP)+"  "+dimStyle.Render("ms")))
	}
	if len(trend.CLS) > 0 {
		b.WriteString(row("CLS", sparkline(trend.CLS)))
	}
}

// --- Helpers ---

func dedup(items []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func statusText(ok bool, text string) string {
	if ok {
		return foundStyle.Render(text)
	}
	return notFoundStyle.Render(text)
}

func titleQuality(length int) string {
	switch {
	case length == 0:
		return notFoundStyle.Render("missing")
	case length < 30:
		return warnStyle.Render("short")
	case length > 60:
		return warnStyle.Render("long")
	default:
		return foundStyle.Render("good length")
	}
}

func descQuality(length int) string {
	switch {
	case length == 0:
		return notFoundStyle.Render("missing")
	case length < 70:
		return warnStyle.Render("short")
	case length > 160:
		return warnStyle.Render("long")
	default:
		return foundStyle.Render("good length")
	}
}

func formatBytes(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	kb := float64(n) / 1024
	if kb < 1024 {
		return fmt.Sprintf("%.1f KB", kb)
	}
	mb := kb / 1024
	return fmt.Sprintf("%.1f MB", mb)
}

func formatCWVMetric(m *seo.MetricBucket, unit string) string {
	var val string
	if unit == "ms" {
		val = fmt.Sprintf("%.0f ms", m.P75)
	} else {
		val = fmt.Sprintf("%.3f", m.P75)
	}

	var ratingStyled string
	switch m.Rating {
	case "good":
		ratingStyled = foundStyle.Render("Good")
	case "needs-improvement":
		ratingStyled = warnStyle.Render("Needs Improvement")
	case "poor":
		ratingStyled = notFoundStyle.Render("Poor")
	}

	dist := dimStyle.Render(fmt.Sprintf("(%.0f%% good, %.0f%% NI, %.0f%% poor)", m.Good, m.NI, m.Poor))
	return fmt.Sprintf("p75 %s  %s  %s", val, ratingStyled, dist)
}

func sparkline(values []float64) string {
	if len(values) == 0 {
		return ""
	}

	blocks := []rune("▁▂▃▄▅▆▇█")

	minVal, maxVal := values[0], values[0]
	for _, v := range values {
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}

	spread := maxVal - minVal
	if spread == 0 {
		spread = 1
	}

	var sb strings.Builder
	for _, v := range values {
		idx := int(math.Round((v - minVal) / spread * float64(len(blocks)-1)))
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		sb.WriteRune(blocks[idx])
	}
	return sb.String()
}

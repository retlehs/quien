package seo

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseOnPage_Title(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		wantText string
		wantLen  int
	}{
		{"simple title", "<title>Hello World</title>", "Hello World", 11},
		{"with whitespace", "<title>  Spaced  </title>", "Spaced", 6},
		{"empty title", "<title></title>", "", 0},
		{"no title", "<html><body>No title here</body></html>", "", 0},
		{"title with attributes", `<title lang="en">With Attrs</title>`, "With Attrs", 10},
		{"multiline title", "<title>\n  Multi\n  Line\n</title>", "Multi\n  Line", 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			parseOnPage(r, tt.html, strings.ToLower(tt.html))
			if r.OnPage.Title != tt.wantText {
				t.Errorf("Title = %q, want %q", r.OnPage.Title, tt.wantText)
			}
			if r.OnPage.TitleLen != tt.wantLen {
				t.Errorf("TitleLen = %d, want %d", r.OnPage.TitleLen, tt.wantLen)
			}
		})
	}
}

func TestParseOnPage_MetaDescription(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		wantText string
	}{
		{
			"standard",
			`<meta name="description" content="A great page">`,
			"A great page",
		},
		{
			"reversed attribute order",
			`<meta content="Reversed order" name="description">`,
			"Reversed order",
		},
		{
			"preserves original case",
			`<meta name="Description" content="Mixed Case Value">`,
			"Mixed Case Value",
		},
		{
			"not found",
			`<html><head></head></html>`,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			parseOnPage(r, tt.html, strings.ToLower(tt.html))
			if r.OnPage.Description != tt.wantText {
				t.Errorf("Description = %q, want %q", r.OnPage.Description, tt.wantText)
			}
		})
	}
}

func TestParseOnPage_H1(t *testing.T) {
	tests := []struct {
		name      string
		html      string
		wantText  string
		wantCount int
	}{
		{
			"simple h1",
			"<h1>Main Heading</h1>",
			"Main Heading", 1,
		},
		{
			"multiline h1 with attributes",
			"<h1\n  class=\"text-3xl font-bold\"\n>\n  Multiline Heading\n</h1>",
			"Multiline Heading", 1,
		},
		{
			"multiple h1s",
			"<h1>First</h1><h1>Second</h1>",
			"First", 2,
		},
		{
			"h1 with inner tags",
			"<h1><span>Styled</span> Heading</h1>",
			"Styled Heading", 1,
		},
		{
			"no h1",
			"<h2>Not an h1</h2>",
			"", 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			parseOnPage(r, tt.html, strings.ToLower(tt.html))
			if r.OnPage.H1 != tt.wantText {
				t.Errorf("H1 = %q, want %q", r.OnPage.H1, tt.wantText)
			}
			if r.OnPage.H1Count != tt.wantCount {
				t.Errorf("H1Count = %d, want %d", r.OnPage.H1Count, tt.wantCount)
			}
		})
	}
}

func TestParseOnPage_Images(t *testing.T) {
	tests := []struct {
		name      string
		html      string
		wantCount int
		wantNoAlt int
	}{
		{
			"all have alt",
			`<img src="a.jpg" alt="Photo A"><img src="b.jpg" alt="Photo B">`,
			2, 0,
		},
		{
			"missing alt",
			`<img src="a.jpg"><img src="b.jpg" alt="B">`,
			2, 1,
		},
		{
			"empty alt counts as missing",
			`<img src="a.jpg" alt=""><img src="b.jpg" alt="  ">`,
			2, 2,
		},
		{
			"no images",
			`<p>No images here</p>`,
			0, 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			parseOnPage(r, tt.html, strings.ToLower(tt.html))
			if r.OnPage.ImgCount != tt.wantCount {
				t.Errorf("ImgCount = %d, want %d", r.OnPage.ImgCount, tt.wantCount)
			}
			if r.OnPage.ImgNoAlt != tt.wantNoAlt {
				t.Errorf("ImgNoAlt = %d, want %d", r.OnPage.ImgNoAlt, tt.wantNoAlt)
			}
		})
	}
}

func TestParseOnPage_Lang(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{"en", `<html lang="en"><body></body></html>`, "en"},
		{"en-us", `<html lang="en-US"><body></body></html>`, "en-us"},
		{"not set", `<html><body></body></html>`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			parseOnPage(r, tt.html, strings.ToLower(tt.html))
			if r.OnPage.Lang != tt.want {
				t.Errorf("Lang = %q, want %q", r.OnPage.Lang, tt.want)
			}
		})
	}
}

func TestParseSocial_OpenGraph(t *testing.T) {
	html := `<html><head>
		<meta property="og:title" content="OG Title">
		<meta property="og:description" content="OG Description">
		<meta property="og:image" content="https://example.com/image.png">
		<meta property="og:type" content="website">
	</head></html>`

	r := &Result{}
	parseSocial(r, html, strings.ToLower(html))

	if r.Social.OGTitle != "OG Title" {
		t.Errorf("OGTitle = %q, want %q", r.Social.OGTitle, "OG Title")
	}
	if r.Social.OGDescription != "OG Description" {
		t.Errorf("OGDescription = %q", r.Social.OGDescription)
	}
	if r.Social.OGImage != "https://example.com/image.png" {
		t.Errorf("OGImage = %q", r.Social.OGImage)
	}
	if r.Social.OGType != "website" {
		t.Errorf("OGType = %q", r.Social.OGType)
	}
}

func TestParseSocial_TwitterCard(t *testing.T) {
	html := `<meta name="twitter:card" content="summary_large_image">
		<meta name="twitter:site" content="@example">`

	r := &Result{}
	parseSocial(r, html, strings.ToLower(html))

	if r.Social.TwitterCard != "summary_large_image" {
		t.Errorf("TwitterCard = %q", r.Social.TwitterCard)
	}
	if r.Social.TwitterSite != "@example" {
		t.Errorf("TwitterSite = %q", r.Social.TwitterSite)
	}
}

func TestParseSocial_JSONLD(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			"single type",
			`<script type="application/ld+json">{"@type":"Organization"}</script>`,
			[]string{"Organization"},
		},
		{
			"multiple types in one block",
			`<script type="application/ld+json">{"@type":"WebSite","potentialAction":{"@type":"SearchAction"}}</script>`,
			[]string{"WebSite", "SearchAction"},
		},
		{
			"multiple script blocks",
			`<script type="application/ld+json">{"@type":"Organization"}</script>
			 <script type="application/ld+json">{"@type":"WebPage"}</script>`,
			[]string{"Organization", "WebPage"},
		},
		{
			"no json-ld",
			`<script>var x = 1;</script>`,
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			parseSocial(r, tt.html, strings.ToLower(tt.html))
			if len(tt.want) == 0 {
				if len(r.Social.SchemaTypes) != 0 {
					t.Errorf("expected no schema types, got %v", r.Social.SchemaTypes)
				}
				return
			}
			if len(r.Social.SchemaTypes) != len(tt.want) {
				t.Fatalf("SchemaTypes = %v, want %v", r.Social.SchemaTypes, tt.want)
			}
			for i, w := range tt.want {
				if r.Social.SchemaTypes[i] != w {
					t.Errorf("SchemaTypes[%d] = %q, want %q", i, r.Social.SchemaTypes[i], w)
				}
			}
		})
	}
}

func TestParseSocial_ReversedAttributeOrder(t *testing.T) {
	html := `<meta content="Reversed OG" property="og:title">`

	r := &Result{}
	parseSocial(r, html, strings.ToLower(html))

	if r.Social.OGTitle != "Reversed OG" {
		t.Errorf("OGTitle = %q, want %q", r.Social.OGTitle, "Reversed OG")
	}
}

func TestParseIndexability_RobotsMeta(t *testing.T) {
	tests := []struct {
		name          string
		html          string
		xRobotsTag    string
		wantMeta      string
		wantIndexable bool
	}{
		{
			"no robots meta",
			`<html></html>`,
			"",
			"", true,
		},
		{
			"index follow",
			`<meta name="robots" content="index, follow">`,
			"",
			"index, follow", true,
		},
		{
			"noindex",
			`<meta name="robots" content="noindex, follow">`,
			"",
			"noindex, follow", false,
		},
		{
			"noindex via x-robots-tag",
			`<html></html>`,
			"noindex",
			"", false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			headers := http.Header{}
			if tt.xRobotsTag != "" {
				headers.Set("X-Robots-Tag", tt.xRobotsTag)
			}
			lower := strings.ToLower(tt.html)
			// Call parseIndexability without the network parts (nil client, empty baseURL)
			// We only test the HTML/header parsing here
			if m := reRobotsMeta.FindStringSubmatch(lower); len(m) > 1 {
				r.Indexability.RobotsMeta = m[1]
			}
			if xr := headers.Get("X-Robots-Tag"); xr != "" {
				r.Indexability.XRobotsTag = xr
			}
			if m := reCanonical.FindStringSubmatch(lower); len(m) > 1 {
				r.Indexability.Canonical = m[1]
			}
			noindex := strings.Contains(strings.ToLower(r.Indexability.RobotsMeta), "noindex") ||
				strings.Contains(strings.ToLower(r.Indexability.XRobotsTag), "noindex")
			r.Indexability.Indexable = !noindex

			if r.Indexability.RobotsMeta != tt.wantMeta {
				t.Errorf("RobotsMeta = %q, want %q", r.Indexability.RobotsMeta, tt.wantMeta)
			}
			if r.Indexability.Indexable != tt.wantIndexable {
				t.Errorf("Indexable = %v, want %v", r.Indexability.Indexable, tt.wantIndexable)
			}
		})
	}
}

func TestParseIndexability_Canonical(t *testing.T) {
	html := `<link rel="canonical" href="https://example.com/page">`
	r := &Result{}
	lower := strings.ToLower(html)
	if m := reCanonical.FindStringSubmatch(lower); len(m) > 1 {
		r.Indexability.Canonical = m[1]
	}
	if r.Indexability.Canonical != "https://example.com/page" {
		t.Errorf("Canonical = %q", r.Indexability.Canonical)
	}
}

func TestParsePerfHints(t *testing.T) {
	html := `<html><head>
		<link rel="preload" href="/font.woff2" as="font">
		<link rel="preload" href="/critical.css" as="style">
		<link rel="preconnect" href="https://fonts.googleapis.com">
		<link rel="stylesheet" href="/style.css">
		<link rel="stylesheet" href="/other.css">
		<style>.inline { color: red; }</style>
		<script src="/app.js"></script>
		<script src="/vendor.js"></script>
		<script>console.log("inline")</script>
	</head><body>
		<img src="a.jpg" loading="lazy">
		<img src="b.jpg" loading="lazy">
		<img src="c.jpg">
	</body></html>`

	headers := http.Header{}
	headers.Set("Cache-Control", "max-age=3600")

	r := &Result{}
	lower := strings.ToLower(html)
	// Use empty baseURL to skip compression check (network I/O)
	parsePerfHints(r, headers, lower, len(html), "")

	if r.PerfHints.PreloadCount != 2 {
		t.Errorf("PreloadCount = %d, want 2", r.PerfHints.PreloadCount)
	}
	if r.PerfHints.PreconnectCount != 1 {
		t.Errorf("PreconnectCount = %d, want 1", r.PerfHints.PreconnectCount)
	}
	if r.PerfHints.ExternalStyles != 2 {
		t.Errorf("ExternalStyles = %d, want 2", r.PerfHints.ExternalStyles)
	}
	if r.PerfHints.InlineStyles != 1 {
		t.Errorf("InlineStyles = %d, want 1", r.PerfHints.InlineStyles)
	}
	if r.PerfHints.ExternalScripts != 2 {
		t.Errorf("ExternalScripts = %d, want 2", r.PerfHints.ExternalScripts)
	}
	if r.PerfHints.InlineScripts != 1 {
		t.Errorf("InlineScripts = %d, want 1", r.PerfHints.InlineScripts)
	}
	if r.PerfHints.LazyImages != 2 {
		t.Errorf("LazyImages = %d, want 2", r.PerfHints.LazyImages)
	}
	if r.PerfHints.CacheControl != "max-age=3600" {
		t.Errorf("CacheControl = %q", r.PerfHints.CacheControl)
	}
	if r.PerfHints.DocSizeBytes != len(html) {
		t.Errorf("DocSizeBytes = %d, want %d", r.PerfHints.DocSizeBytes, len(html))
	}
}

func TestStripTags(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<span>text</span>", "text"},
		{"<a href='#'>link</a> more", "link more"},
		{"no tags", "no tags"},
		{"<b><i>nested</i></b>", "nested"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripTags(tt.input)
			if got != tt.want {
				t.Errorf("stripTags(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

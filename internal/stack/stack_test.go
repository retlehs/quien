package stack

import (
	"net/http"
	"slices"
	"strings"
	"testing"
)

func sliceContains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}

func TestIsWordPress(t *testing.T) {
	tests := []struct {
		name string
		html string
		want bool
	}{
		{"REST API link", `<link rel="https://api.w.org/" href="https://example.com/wp-json/" />`, true},
		{"wp-includes", `<script src="/wp-includes/js/jquery.min.js"></script>`, true},
		{"wp-content", `<link href="/wp-content/themes/sage/style.css">`, true},
		{"wp-emoji", `wp-emoji-release.min.js`, true},
		{"wp-block class", `<div class="wp-block-group">`, true},
		{"gutenberg comment", `<!-- wp:paragraph -->`, true},
		{"wp-json", `<link href="/wp-json/wp/v2/posts">`, true},
		{"xmlrpc", `<link rel="pingback" href="/xmlrpc.php">`, true},
		{"wp-embed", `<script src="wp-embed.min.js"></script>`, true},
		{"global-styles", `<style id="global-styles-inline-css">`, true},
		{"not wordpress", `<html><head><title>Hello</title></head></html>`, false},
		{"react app", `<div id="root"></div><script src="/static/js/main.js"></script>`, false},
		{"mentions wordpress in text", `<p>We migrated from WordPress to Hugo</p>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWordPress(tt.html)
			if got != tt.want {
				t.Errorf("isWordPress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectWPPlugins(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		want    []string
		notWant []string
	}{
		{
			name: "WooCommerce from asset path",
			html: `<link href="/app/plugins/woocommerce/assets/style.css">`,
			want: []string{"WooCommerce"},
		},
		{
			name: "WooCommerce from block class",
			html: `<div class="wc-block-grid">`,
			want: []string{"WooCommerce"},
		},
		{
			name: "Elementor",
			html: `<link href="/wp-content/plugins/elementor/assets/style.css"><div class="elementor-kit-123">`,
			want: []string{"Elementor"},
		},
		{
			name: "Yoast from comment",
			html: `<!-- This site is optimized with the Yoast SEO plugin -->`,
			want: []string{"Yoast SEO"},
		},
		{
			name:    "no false positive from content",
			html:    `<p>We recommend using Wordfence for security</p>`,
			notWant: []string{"Wordfence"},
		},
		{
			name: "multiple plugins",
			html: `<link href="/wp-content/plugins/gravityforms/style.css"><link href="/wp-content/plugins/contact-form-7/style.css"><div class="wpcf7-form">`,
			want: []string{"Gravity Forms", "Contact Form 7"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			detectWPPlugins(r, strings.ToLower(tt.html))

			for _, w := range tt.want {
				if !sliceContains(r.Plugins, w) {
					t.Errorf("expected plugin %q, got %v", w, r.Plugins)
				}
			}
			for _, nw := range tt.notWant {
				if sliceContains(r.Plugins, nw) {
					t.Errorf("unexpected plugin %q in %v", nw, r.Plugins)
				}
			}
		})
	}
}

func TestDetectCMS(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "Magento from data-mage-init",
			html: `<div data-mage-init='{"someWidget":{}}'></div>`,
			want: "Magento",
		},
		{
			name: "Magento from static path",
			html: `<link href="/static/frontend/magento/luma/en_US/css/styles.css">`,
			want: "Magento",
		},
		{
			name: "Magento not detected from image MIME types",
			html: `<link rel="icon" type="image/png" href="/fav.png"><img src="data:image/svg+xml;base64,abc">`,
			want: "",
		},
		{
			name: "PrestaShop from module path",
			html: `<link href="/modules/ps_shoppingcart/css/cart.css">`,
			want: "PrestaShop",
		},
		{
			name: "PrestaShop not detected from prose mention",
			html: `<p>We migrated from prestashop last year.</p>`,
			want: "",
		},
		{
			name: "Webflow from data-wf-page",
			html: `<html data-wf-page="abc123" data-wf-site="def456">`,
			want: "Webflow",
		},
		{
			name: "Webflow not detected from a link to webflow.com",
			html: `<a href="https://webflow.com">Built with Webflow</a>`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			detectCMS(r, http.Header{}, strings.ToLower(tt.html))
			if r.CMS != tt.want {
				t.Errorf("expected CMS %q, got %q", tt.want, r.CMS)
			}
		})
	}
}

func TestDetectJSLibs(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "React",
			html: `<script src="/static/react.production.min.js"></script>`,
			want: []string{"React"},
		},
		{
			name: "Alpine from attributes",
			html: `<div x-data="{ open: false }"><button x-on:click="open = !open">`,
			want: []string{"Alpine.js"},
		},
		{
			name: "htmx from attributes",
			html: `<button hx-get="/api/data" hx-swap="innerHTML">Load</button>`,
			want: []string{"htmx"},
		},
		{
			name: "jQuery",
			html: `<script src="https://cdn.jsdelivr.net/npm/jquery.min.js"></script>`,
			want: []string{"jQuery"},
		},
		{
			name: "Next.js",
			html: `<script id="__next_data__" type="application/json">{"page":"/"}</script>`,
			want: []string{"Next.js"},
		},
		{
			name: "Preact from submodule import",
			html: `<script type="importmap">{"imports":{"preact/hooks":"https://esm.sh/preact/hooks"}}</script>`,
			want: []string{"Preact"},
		},
		{
			name: "Preact not detected from a tag URL",
			html: `<a href="/tags/preact/" class="tag">#Preact</a>`,
			want: nil,
		},
		{
			name: "no false positives",
			html: `<html><body><p>Just a simple page</p></body></html>`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			detectJSLibs(r, strings.ToLower(tt.html))

			if len(tt.want) == 0 {
				if len(r.JSLibs) != 0 {
					t.Errorf("expected no JS libs, got %v", r.JSLibs)
				}
				return
			}
			for _, w := range tt.want {
				if !sliceContains(r.JSLibs, w) {
					t.Errorf("expected %q, got %v", w, r.JSLibs)
				}
			}
		})
	}
}

func TestDetectCSSLibs(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "Bootstrap",
			html: `<link href="bootstrap.min.css"><script src="bootstrap.min.js">`,
			want: []string{"Bootstrap"},
		},
		{
			name: "Tailwind from utility classes",
			html: `<div class="flex items-center justify-between bg-white text-sm px-4 py-2 rounded-lg max-w-7xl grid gap-4">`,
			want: []string{"Tailwind CSS"},
		},
		{
			name: "not enough tailwind classes",
			html: `<div class="flex items-center">`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Result{}
			detectCSSLibs(r, strings.ToLower(tt.html))

			if len(tt.want) == 0 {
				if len(r.CSSLibs) != 0 {
					t.Errorf("expected no CSS libs, got %v", r.CSSLibs)
				}
				return
			}
			for _, w := range tt.want {
				if !sliceContains(r.CSSLibs, w) {
					t.Errorf("expected %q, got %v", w, r.CSSLibs)
				}
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"cdn.jsdelivr.net", "jsdelivr.net"},
		{"www.google.com", "google.com"},
		{"api.cdn.example.co.uk", "example.co.uk"},
		{"example.com", "example.com"},
		{"sub.domain.example.com", "example.com"},
		{"fonts.googleapis.com", "fonts.googleapis.com"},
		{"example.com:443", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractDomain(tt.input)
			if got != tt.want {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseExternalServices(t *testing.T) {
	html := `<html>
<head>
	<script src="https://cdn.jsdelivr.net/npm/alpine.js"></script>
	<script src="https://www.googletagmanager.com/gtag/js"></script>
	<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">
	<script src="/local/script.js"></script>
	<link href="/style.css" rel="stylesheet">
</head>
</html>`

	r := &Result{}
	parseExternalServices(r, html, "example.com")

	if len(r.ExternalSvc) != 3 {
		t.Fatalf("ExternalSvc count = %d, want 3 (local scripts excluded)", len(r.ExternalSvc))
	}

	domains := make(map[string]bool)
	for _, svc := range r.ExternalSvc {
		domains[svc.Domain] = true
	}

	for _, want := range []string{"jsdelivr.net", "googletagmanager.com", "fonts.googleapis.com"} {
		if !domains[want] {
			t.Errorf("expected external service %q, got %v", want, r.ExternalSvc)
		}
	}
}

func TestParseExternalServices_ExcludesSameDomain(t *testing.T) {
	html := `<script src="https://example.com/app.js"></script>
<script src="https://www.example.com/other.js"></script>
<script src="https://cdn.external.com/lib.js"></script>`

	r := &Result{}
	parseExternalServices(r, html, "example.com")

	if len(r.ExternalSvc) != 1 {
		t.Errorf("ExternalSvc count = %d, want 1", len(r.ExternalSvc))
	}
	if len(r.ExternalSvc) > 0 && r.ExternalSvc[0].Domain != "external.com" {
		t.Errorf("expected external.com, got %q", r.ExternalSvc[0].Domain)
	}
}

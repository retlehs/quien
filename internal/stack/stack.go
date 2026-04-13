package stack

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

type Result struct {
	CMS         string
	Plugins     []string // detected CMS plugins/extensions
	PoweredBy   string   // raw X-Powered-By header
	Server      string
	CDN         string
	Hosting     string
	JSLibs      []string
	CSSLibs     []string
	ExternalSvc []ExternalService // parsed from script/link tags
}

type ExternalService struct {
	Domain string
	Type   string // "script", "stylesheet", "prefetch", etc.
}

const (
	timeout     = 10 * time.Second
	maxBodySize = 512 * 1024
)

func Detect(domain string) (*Result, error) {
	page, err := FetchPage(domain)
	if err != nil {
		return nil, err
	}
	return DetectFromPage(page.Headers, page.Body, domain), nil
}

// DetectFromPage runs stack detection on pre-fetched page data.
func DetectFromPage(headers http.Header, body []byte, domain string) *Result {
	html := string(body)
	lower := strings.ToLower(html)

	r := &Result{}

	// Direct from headers — no interpretation
	if s := headers.Get("Server"); s != "" {
		r.Server = s
	}
	if p := headers.Get("X-Powered-By"); p != "" {
		r.PoweredBy = p
	}

	detectCDN(r, headers)
	detectHosting(r, headers)
	detectCMS(r, headers, lower)
	detectJSLibs(r, lower)
	detectCSSLibs(r, lower)
	parseExternalServices(r, html, domain)

	sort.Strings(r.Plugins)
	sort.Strings(r.JSLibs)
	sort.Strings(r.CSSLibs)

	return r
}

// PageData holds the result of a page fetch.
type PageData struct {
	Headers http.Header
	Body    []byte
	BaseURL string // the URL that succeeded (https:// or http://)
}

// FetchPage fetches a domain's HTML page, trying HTTPS first with HTTP fallback.
func FetchPage(domain string) (*PageData, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}

	baseURL := "https://" + domain
	resp, err := client.Get(baseURL)
	if err != nil {
		baseURL = "http://" + domain
		resp, err = client.Get(baseURL)
		if err != nil {
			return nil, err
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, err
	}

	// Use the final URL after redirects (e.g. example.com -> www.example.com)
	finalURL := resp.Request.URL.Scheme + "://" + resp.Request.URL.Host

	return &PageData{Headers: resp.Header, Body: body, BaseURL: finalURL}, nil
}

func detectCDN(r *Result, h http.Header) {
	if h.Get("Cf-Ray") != "" || strings.Contains(strings.ToLower(h.Get("Server")), "cloudflare") {
		r.CDN = "Cloudflare"
	} else if h.Get("X-Fastly-Request-Id") != "" {
		r.CDN = "Fastly"
	} else if h.Get("X-Amz-Cf-Id") != "" || h.Get("X-Amz-Cf-Pop") != "" {
		r.CDN = "Amazon CloudFront"
	} else if h.Get("X-Vercel-Id") != "" {
		r.CDN = "Vercel"
	} else if strings.Contains(strings.ToLower(h.Get("Server")), "netlify") {
		r.CDN = "Netlify"
	}
}

func detectHosting(r *Result, h http.Header) {
	if strings.Contains(h.Get("X-Powered-By"), "WP Engine") {
		r.Hosting = "WP Engine"
	} else if h.Get("X-Kinsta-Cache") != "" {
		r.Hosting = "Kinsta"
	} else if h.Get("X-Pantheon-Styx-Hostname") != "" {
		r.Hosting = "Pantheon"
	} else if h.Get("X-Github-Request-Id") != "" {
		r.Hosting = "GitHub Pages"
	} else if h.Get("Fly-Request-Id") != "" {
		r.Hosting = "Fly.io"
	} else if h.Get("X-Vercel-Id") != "" && r.CDN != "Vercel" {
		r.Hosting = "Vercel"
	}
}

func isWordPress(html string) bool {
	// Multiple reliable signals — any one is enough
	wpSignals := []string{
		`rel="https://api.w.org/"`, // REST API discovery link
		"/wp-includes/",            // core directory (can't be renamed)
		"/wp-content/",             // default content dir
		"wp-emoji-release.min.js",  // emoji support script
		"wp-block-",                // Gutenberg block classes
		"<!-- wp:",                 // Gutenberg block comments
		"/wp-json/",                // REST API
		"/xmlrpc.php",              // XML-RPC endpoint
		"wp-embed.min.js",          // embed script
		"global-styles-inline-css", // block theme styles
	}
	for _, sig := range wpSignals {
		if strings.Contains(html, sig) {
			return true
		}
	}
	return false
}

func detectCMS(r *Result, h http.Header, html string) {
	// WordPress
	if isWordPress(html) {
		r.CMS = "WordPress"
		if m := regexp.MustCompile(`content="wordpress\s*([\d.]+)?"`).FindStringSubmatch(html); len(m) > 1 && m[1] != "" {
			r.CMS = "WordPress " + m[1]
		}
		detectWPPlugins(r, html)
		return
	}
	// Shopify
	if strings.Contains(html, "cdn.shopify.com") || strings.Contains(html, "shopify.theme") {
		r.CMS = "Shopify"
		return
	}
	// Squarespace
	if strings.Contains(html, "static.squarespace.com") || strings.Contains(html, "squarespace-cdn.com") {
		r.CMS = "Squarespace"
		return
	}
	// Wix
	if strings.Contains(html, "wixstatic.com") {
		r.CMS = "Wix"
		return
	}
	// Ghost
	if m := regexp.MustCompile(`content="ghost\s*([\d.]+)?"`).FindStringSubmatch(html); len(m) > 0 {
		r.CMS = "Ghost"
		if m[1] != "" {
			r.CMS = "Ghost " + m[1]
		}
		return
	}
	// Drupal
	if h.Get("X-Drupal-Cache") != "" || strings.Contains(html, "drupal.settings") {
		r.CMS = "Drupal"
		return
	}
	// Joomla
	if strings.Contains(html, "/media/jui/") || regexp.MustCompile(`content="joomla`).MatchString(html) {
		r.CMS = "Joomla"
		return
	}
	// Hugo
	if regexp.MustCompile(`content="hugo`).MatchString(html) {
		r.CMS = "Hugo"
		return
	}
	// Craft CMS
	if strings.Contains(html, "cpresources") {
		r.CMS = "Craft CMS"
		return
	}
	// Magento
	if strings.Contains(html, "/static/frontend/magento/") || strings.Contains(html, "magento_") || strings.Contains(html, "mage/") {
		r.CMS = "Magento"
		return
	}
	// PrestaShop
	if strings.Contains(html, "prestashop") || strings.Contains(html, "/modules/ps_") {
		r.CMS = "PrestaShop"
		return
	}
	// Typo3
	if strings.Contains(html, "/typo3/") || strings.Contains(html, "typo3conf") {
		r.CMS = "Typo3"
		return
	}
	// Webflow
	if strings.Contains(html, "webflow.com") || strings.Contains(html, "wf-page") {
		r.CMS = "Webflow"
		return
	}
}

func detectWPPlugins(r *Result, html string) {
	// Only use path-based patterns (/plugin-slug/) and very specific
	// HTML attribute patterns (class="prefix-", id="prefix-") to avoid
	// false positives from page content mentioning plugin names.
	plugins := []struct {
		name     string
		patterns []string
	}{
		{"ACF", []string{"/advanced-custom-fields/"}},
		{"Akismet", []string{"/akismet/"}},
		{"All in One SEO", []string{"/all-in-one-seo-pack/"}},
		{"Autoptimize", []string{"/autoptimize/", "<!-- autoptimize"}},
		{"Beaver Builder", []string{"/bb-plugin/", "class=\"fl-builder", "class=\"fl-row"}},
		{"Bricks", []string{"/bricks/", "class=\"brxe-"}},
		{"Contact Form 7", []string{"/contact-form-7/", "class=\"wpcf7"}},
		{"Divi", []string{"/et-core/", "/divi/", "class=\"et_pb_"}},
		{"Elementor", []string{"/elementor/", "elementor-kit-", "e-lazyloaded"}},
		{"FlyingPress", []string{"/flying-press/"}},
		{"GeneratePress", []string{"/gp-premium/", "generatepress"}},
		{"Gravity Forms", []string{"/gravityforms/", "class=\"gform_wrapper", "class=\"gfield"}},
		{"GTM4WP", []string{"/duracelltomi-google-tag-manager/", "<!-- google tag manager for wordpress by gtm4wp"}},
		{"Jetpack", []string{"/jetpack/"}},
		{"Kadence", []string{"/kadence-blocks/"}},
		{"LiteSpeed Cache", []string{"/litespeed-cache/"}},
		{"MonsterInsights", []string{"/google-analytics-for-wordpress/"}},
		{"Oxygen", []string{"/oxygen/", "class=\"ct-section"}},
		{"Perfmatters", []string{"/perfmatters/"}},
		{"Polylang", []string{"/polylang/"}},
		{"Rank Math", []string{"/seo-by-rank-math/", "<!-- search engine optimization by rank math"}},
		{"Redirection", []string{"/redirection/"}},
		{"SEOPress", []string{"/wp-seopress/", "<!-- seopress"}},
		{"Slim SEO", []string{"/slim-seo/"}},
		{"Sucuri", []string{"/sucuri-scanner/"}},
		{"The SEO Framework", []string{"/autodescription/", "<!-- the seo framework by sybre waaijer"}},
		{"W3 Total Cache", []string{"/w3-total-cache/", "<!-- w3 total cache"}},
		{"WooCommerce", []string{"/woocommerce/", "wc-block-", "wc-cart-fragments", "is-type-product"}},
		{"WP Fastest Cache", []string{"/wp-fastest-cache/", "<!-- wp fastest cache"}},
		{"WP Rocket", []string{"/wp-rocket/", "<!-- this site is optimized with wp rocket"}},
		{"WP Super Cache", []string{"/wp-super-cache/", "<!-- wp super cache"}},
		{"WP-Optimize", []string{"/wp-optimize/"}},
		{"WPBakery", []string{"/js_composer/", "class=\"wpb_row", "class=\"vc_row"}},
		{"WPML", []string{"/sitepress-multilingual-cms/"}},
		{"Wordfence", []string{"/wordfence/"}},
		{"Yoast SEO", []string{"/wordpress-seo/", "yoast-schema-graph", "<!-- this site is optimized with the yoast"}},
	}

	for _, p := range plugins {
		for _, pattern := range p.patterns {
			if strings.Contains(html, pattern) {
				r.Plugins = append(r.Plugins, p.name)
				break
			}
		}
	}
}

func detectJSLibs(r *Result, html string) {
	libs := []struct {
		name     string
		patterns []string
	}{
		{"Alpine.js", []string{"alpine.js", "alpine.min.js", " x-data=", " x-bind:", " x-on:"}},
		{"Angular", []string{"ng-version=", " ng-app="}},
		{"Backbone.js", []string{"backbone.min.js", "backbone.js"}},
		{"Astro", []string{"data-astro-"}},
		{"D3.js", []string{"d3.min.js", "d3-selection"}},
		{"Ember.js", []string{"ember.min.js", "ember.js", "ember-view"}},
		{"Gatsby", []string{"___gatsby", "/gatsby-"}},
		{"GSAP", []string{"gsap.min.js"}},
		{"htmx", []string{"htmx.org", "htmx.min.js", " hx-get=", " hx-post=", " hx-swap="}},
		{"jQuery", []string{"jquery.min.js", "jquery.js", "jquery-migrate"}},
		{"Lit", []string{"lit-html", "lit-element"}},
		{"Livewire", []string{"livewire/livewire", " wire:"}},
		{"Next.js", []string{"__next_data__", "/_next/"}},
		{"Nuxt", []string{"__nuxt", "/_nuxt/"}},
		{"Preact", []string{"preact.min.js", "preact/"}},
		{"React", []string{"react.production.min.js", "react-dom", "data-reactroot", "_reactlistening"}},
		{"Remix", []string{"__remix"}},
		{"Solid.js", []string{"solid-js", "_$createcomponent"}},
		{"Stimulus", []string{" data-controller="}},
		{"Svelte", []string{"__svelte", ".svelte-"}},
		{"SvelteKit", []string{"__sveltekit"}},
		{"Three.js", []string{"three.min.js", "three.module.js"}},
		{"Turbo", []string{"turbo-frame", " data-turbo="}},
		{"Vue.js", []string{"vue.min.js", "vue.global", "vue.runtime", "__vue_app__"}},
	}

	for _, lib := range libs {
		for _, p := range lib.patterns {
			if strings.Contains(html, p) {
				r.JSLibs = append(r.JSLibs, lib.name)
				break
			}
		}
	}
}

func detectCSSLibs(r *Result, html string) {
	libs := []struct {
		name     string
		patterns []string
	}{
		{"Bootstrap", []string{"bootstrap.min.css", "bootstrap.min.js"}},
		{"Bulma", []string{"bulma.min.css", "bulma.css"}},
		{"Foundation", []string{"foundation.min.css"}},
	}

	// Tailwind heuristic: multiple utility class patterns
	twClasses := []string{" flex ", "items-center", "justify-between", " bg-", " text-sm", " px-", " py-", " rounded-", " max-w-", " grid ", " gap-"}
	matches := 0
	for _, c := range twClasses {
		if strings.Contains(html, c) {
			matches++
		}
	}
	if matches >= 5 {
		r.CSSLibs = append(r.CSSLibs, "Tailwind CSS")
	}

	for _, lib := range libs {
		for _, p := range lib.patterns {
			if strings.Contains(html, p) {
				r.CSSLibs = append(r.CSSLibs, lib.name)
				break
			}
		}
	}
}

// parseExternalServices extracts external domains from script src and link href tags.
var (
	scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	linkHrefRe  = regexp.MustCompile(`<link[^>]+href=["']([^"']+)["']`)
)

func parseExternalServices(r *Result, html string, siteDomain string) {
	seen := make(map[string]bool)
	siteDomain = strings.ToLower(siteDomain)

	// Also ignore www. variant
	siteVariants := []string{siteDomain, "www." + siteDomain}

	addExternal := func(rawURL, svcType string) {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			return
		}
		host := strings.ToLower(u.Host)

		// Skip same-domain resources
		for _, v := range siteVariants {
			if host == v {
				return
			}
		}

		// Extract the registrable domain (last two parts for most, three for co.uk etc.)
		domain := extractDomain(host)
		if domain == "" {
			return
		}

		if seen[domain] {
			return
		}
		seen[domain] = true

		r.ExternalSvc = append(r.ExternalSvc, ExternalService{
			Domain: domain,
			Type:   svcType,
		})
	}

	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		addExternal(m[1], "script")
	}
	for _, m := range linkHrefRe.FindAllStringSubmatch(html, -1) {
		addExternal(m[1], "stylesheet")
	}

	sort.Slice(r.ExternalSvc, func(i, j int) bool {
		return r.ExternalSvc[i].Domain < r.ExternalSvc[j].Domain
	})
}

// extractDomain pulls the registrable domain from a hostname.
// e.g. "cdn.jsdelivr.net" -> "jsdelivr.net", "www.google.com" -> "google.com"
func extractDomain(host string) string {
	// Remove port
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Use the public suffix list for correct domain extraction
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback: last two parts
		parts := strings.Split(host, ".")
		if len(parts) < 2 {
			return host
		}
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

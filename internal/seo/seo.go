package seo

import (
	"crypto/tls"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/retlehs/quien/internal/stack"
)

// Result holds all SEO analysis data for a domain.
type Result struct {
	Indexability Indexability `json:"indexability"`
	OnPage       OnPage       `json:"on_page"`
	Social       Social       `json:"social"`
	PerfHints    PerfHints    `json:"perf_hints"`
	CWV          *CWVData     `json:"cwv,omitempty"`
	Trend        *CWVTrend    `json:"cwv_trend,omitempty"`
	CrUXKeySet   bool         `json:"-"`
}

type Indexability struct {
	RobotsTxt    string `json:"robots_txt,omitempty"`
	RobotsMeta   string `json:"robots_meta,omitempty"`
	XRobotsTag   string `json:"x_robots_tag,omitempty"`
	Canonical    string `json:"canonical,omitempty"`
	Indexable    bool   `json:"indexable"`
	SitemapFound bool   `json:"sitemap_found"`
	SitemapURL   string `json:"sitemap_url,omitempty"`
}

type OnPage struct {
	Title       string `json:"title,omitempty"`
	TitleLen    int    `json:"title_length"`
	Description string `json:"meta_description,omitempty"`
	DescLen     int    `json:"description_length"`
	H1          string `json:"h1,omitempty"`
	H1Count     int    `json:"h1_count"`
	ImgCount    int    `json:"img_count"`
	ImgNoAlt    int    `json:"img_no_alt"`
	Lang        string `json:"lang,omitempty"`
}

type Social struct {
	OGTitle       string   `json:"og_title,omitempty"`
	OGDescription string   `json:"og_description,omitempty"`
	OGImage       string   `json:"og_image,omitempty"`
	OGType        string   `json:"og_type,omitempty"`
	TwitterCard   string   `json:"twitter_card,omitempty"`
	TwitterSite   string   `json:"twitter_site,omitempty"`
	SchemaTypes   []string `json:"schema_types,omitempty"`
}

type PerfHints struct {
	Compressed      bool   `json:"compressed"`
	Encoding        string `json:"encoding,omitempty"`
	CacheControl    string `json:"cache_control,omitempty"`
	PreloadCount    int    `json:"preload_count"`
	PreconnectCount int    `json:"preconnect_count"`
	LazyImages      int    `json:"lazy_images"`
	InlineScripts   int    `json:"inline_scripts"`
	ExternalScripts int    `json:"external_scripts"`
	InlineStyles    int    `json:"inline_styles"`
	ExternalStyles  int    `json:"external_styles"`
	DocSizeBytes    int    `json:"doc_size_bytes"`
}

const (
	timeout     = 10 * time.Second
	maxBodySize = 512 * 1024
)

// Analyze fetches a domain's HTML and HTTP headers and extracts SEO signals.
func Analyze(domain string) (*Result, error) {
	page, err := stack.FetchPage(domain)
	if err != nil {
		return nil, err
	}
	return AnalyzeWithPage(page, domain), nil
}

// AnalyzeWithPage runs SEO analysis on pre-fetched page data.
// Note: this still performs network I/O (robots.txt, compression check, CrUX API).
func AnalyzeWithPage(page *stack.PageData, domain string) *Result {
	rawHTML := string(page.Body)
	lower := strings.ToLower(rawHTML)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			DialContext:     (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}

	r := &Result{}

	parseIndexability(r, client, page.BaseURL, page.Headers, lower)
	parseOnPage(r, rawHTML, lower)
	parseSocial(r, rawHTML, lower)
	parsePerfHints(r, page.Headers, lower, len(page.Body), page.BaseURL)

	// CrUX integration — populated by crux.go if API key is set.
	// Try both the final origin (after redirects) and the input domain,
	// since CrUX may index data under either.
	inputOrigin := page.BaseURL[:strings.Index(page.BaseURL, "://")+3] + domain
	fetchCrUX(r, page.BaseURL, inputOrigin)

	return r
}

// --- Indexability ---

func parseIndexability(r *Result, client *http.Client, baseURL string, headers http.Header, lower string) {
	// robots meta tag
	if m := reRobotsMeta.FindStringSubmatch(lower); len(m) > 1 {
		r.Indexability.RobotsMeta = m[1]
	}

	// X-Robots-Tag header
	if xr := headers.Get("X-Robots-Tag"); xr != "" {
		r.Indexability.XRobotsTag = xr
	}

	// canonical
	if m := reCanonical.FindStringSubmatch(lower); len(m) > 1 {
		r.Indexability.Canonical = m[1]
	}

	// indexable = no noindex in robots meta or X-Robots-Tag
	noindex := strings.Contains(strings.ToLower(r.Indexability.RobotsMeta), "noindex") ||
		strings.Contains(strings.ToLower(r.Indexability.XRobotsTag), "noindex")
	r.Indexability.Indexable = !noindex

	// robots.txt + sitemap discovery
	fetchRobotsTxt(r, client, baseURL)
}

func fetchRobotsTxt(r *Result, client *http.Client, baseURL string) {
	resp, err := client.Get(baseURL + "/robots.txt")
	if err != nil {
		r.Indexability.RobotsTxt = "unreachable"
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		r.Indexability.RobotsTxt = "not found"
		return
	}
	r.Indexability.RobotsTxt = "found"

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(trimmed), "sitemap:") {
			url := strings.TrimSpace(trimmed[len("sitemap:"):])
			if url != "" {
				r.Indexability.SitemapFound = true
				r.Indexability.SitemapURL = url
				return
			}
		}
	}

	// Try well-known sitemap path if not in robots.txt
	sitemapResp, err := client.Head(baseURL + "/sitemap.xml")
	if err == nil {
		_ = sitemapResp.Body.Close()
		if sitemapResp.StatusCode == 200 {
			r.Indexability.SitemapFound = true
			r.Indexability.SitemapURL = baseURL + "/sitemap.xml"
		}
	}
}

// --- On-Page ---

func parseOnPage(r *Result, rawHTML, lower string) {
	// Title
	if m := reTitle.FindStringSubmatch(rawHTML); len(m) > 1 {
		r.OnPage.Title = html.UnescapeString(strings.TrimSpace(m[1]))
		r.OnPage.TitleLen = len(r.OnPage.Title)
	}

	// Meta description (handles both attribute orders)
	if desc := metaName(lower, rawHTML, "description"); desc != "" {
		r.OnPage.Description = desc
		r.OnPage.DescLen = len(desc)
	}

	// H1
	h1Matches := reH1.FindAllStringSubmatch(rawHTML, -1)
	r.OnPage.H1Count = len(h1Matches)
	if len(h1Matches) > 0 {
		r.OnPage.H1 = html.UnescapeString(strings.TrimSpace(stripTags(h1Matches[0][1])))
	}

	// Images
	imgMatches := reImg.FindAllString(lower, -1)
	r.OnPage.ImgCount = len(imgMatches)
	for _, img := range imgMatches {
		if !reImgAlt.MatchString(img) || reImgAltEmpty.MatchString(img) {
			r.OnPage.ImgNoAlt++
		}
	}

	// Lang
	if m := reLang.FindStringSubmatch(lower); len(m) > 1 {
		r.OnPage.Lang = m[1]
	}
}

// --- Social / Structured Data ---

func parseSocial(r *Result, rawHTML, lower string) {
	r.Social.OGTitle = metaProperty(lower, rawHTML, "og:title")
	r.Social.OGDescription = metaProperty(lower, rawHTML, "og:description")
	r.Social.OGImage = metaProperty(lower, rawHTML, "og:image")
	r.Social.OGType = metaProperty(lower, rawHTML, "og:type")
	r.Social.TwitterCard = metaName(lower, rawHTML, "twitter:card")
	r.Social.TwitterSite = metaName(lower, rawHTML, "twitter:site")

	// JSON-LD @type extraction
	for _, m := range reJSONLD.FindAllStringSubmatch(rawHTML, -1) {
		if len(m) > 1 {
			for _, tm := range reSchemaType.FindAllStringSubmatch(m[1], -1) {
				if len(tm) > 1 {
					t := strings.TrimSpace(tm[1])
					if t != "" {
						r.Social.SchemaTypes = append(r.Social.SchemaTypes, t)
					}
				}
			}
		}
	}
}

func metaProperty(lower, originalHTML, prop string) string {
	re := regexp.MustCompile(`<meta[^>]+property=["']` + regexp.QuoteMeta(prop) + `["'][^>]+content=["']([^"']*)["']`)
	if m := re.FindStringSubmatch(lower); len(m) > 1 {
		reOrig := regexp.MustCompile(`(?i)<meta[^>]+property=["']` + regexp.QuoteMeta(prop) + `["'][^>]+content=["']([^"']*)["']`)
		if mo := reOrig.FindStringSubmatch(originalHTML); len(mo) > 1 {
			return html.UnescapeString(strings.TrimSpace(mo[1]))
		}
		return html.UnescapeString(strings.TrimSpace(m[1]))
	}
	// Try reversed attribute order: content before property
	re2 := regexp.MustCompile(`<meta[^>]+content=["']([^"']*)["'][^>]+property=["']` + regexp.QuoteMeta(prop) + `["']`)
	if m := re2.FindStringSubmatch(lower); len(m) > 1 {
		re2Orig := regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']*)["'][^>]+property=["']` + regexp.QuoteMeta(prop) + `["']`)
		if mo := re2Orig.FindStringSubmatch(originalHTML); len(mo) > 1 {
			return html.UnescapeString(strings.TrimSpace(mo[1]))
		}
		return html.UnescapeString(strings.TrimSpace(m[1]))
	}
	return ""
}

func metaName(lower, originalHTML, name string) string {
	re := regexp.MustCompile(`<meta[^>]+name=["']` + regexp.QuoteMeta(name) + `["'][^>]+content=["']([^"']*)["']`)
	if m := re.FindStringSubmatch(lower); len(m) > 1 {
		reOrig := regexp.MustCompile(`(?i)<meta[^>]+name=["']` + regexp.QuoteMeta(name) + `["'][^>]+content=["']([^"']*)["']`)
		if mo := reOrig.FindStringSubmatch(originalHTML); len(mo) > 1 {
			return html.UnescapeString(strings.TrimSpace(mo[1]))
		}
		return html.UnescapeString(strings.TrimSpace(m[1]))
	}
	// Reversed attribute order
	re2 := regexp.MustCompile(`<meta[^>]+content=["']([^"']*)["'][^>]+name=["']` + regexp.QuoteMeta(name) + `["']`)
	if m := re2.FindStringSubmatch(lower); len(m) > 1 {
		re2Orig := regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']*)["'][^>]+name=["']` + regexp.QuoteMeta(name) + `["']`)
		if mo := re2Orig.FindStringSubmatch(originalHTML); len(mo) > 1 {
			return html.UnescapeString(strings.TrimSpace(mo[1]))
		}
		return html.UnescapeString(strings.TrimSpace(m[1]))
	}
	return ""
}

// --- Perf Hints ---

func parsePerfHints(r *Result, headers http.Header, lower string, bodyLen int, baseURL string) {
	r.PerfHints.DocSizeBytes = bodyLen

	// Compression — Go's http.Client transparently decompresses and strips
	// Content-Encoding, so we do a separate HEAD with explicit Accept-Encoding
	// to check what the server actually supports.
	checkCompression(r, baseURL)

	// Cache-Control
	if cc := headers.Get("Cache-Control"); cc != "" {
		r.PerfHints.CacheControl = cc
	}

	// Preload / preconnect links
	r.PerfHints.PreloadCount = len(rePreload.FindAllString(lower, -1))
	r.PerfHints.PreconnectCount = len(rePreconnect.FindAllString(lower, -1))

	// Lazy images
	r.PerfHints.LazyImages = len(reLazyImg.FindAllString(lower, -1))

	// Scripts
	r.PerfHints.InlineScripts = len(reInlineScript.FindAllString(lower, -1))
	r.PerfHints.ExternalScripts = len(reExternalScript.FindAllString(lower, -1))

	// Styles
	r.PerfHints.InlineStyles = len(reInlineStyle.FindAllString(lower, -1))
	r.PerfHints.ExternalStyles = len(reExternalStylesheet.FindAllString(lower, -1))
}

func checkCompression(r *Result, baseURL string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableCompression: true,
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: false},
			DialContext:        (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}

	req, err := http.NewRequest("HEAD", baseURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if enc := resp.Header.Get("Content-Encoding"); enc != "" {
		r.PerfHints.Compressed = true
		r.PerfHints.Encoding = enc
	}
}

// --- Tag stripping helper ---

func stripTags(s string) string {
	return reStripTags.ReplaceAllString(s, "")
}

// --- Compiled regexes ---

var (
	reRobotsMeta  = regexp.MustCompile(`<meta[^>]+name=["']robots["'][^>]+content=["']([^"']*)["']`)
	reCanonical   = regexp.MustCompile(`<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']`)
	reTitle       = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reH1          = regexp.MustCompile(`(?is)<h1[^>]*>(.*?)</h1>`)
	reImg         = regexp.MustCompile(`(?i)<img[^>]*>`)
	reImgAlt      = regexp.MustCompile(`(?i)\balt=["']`)
	reImgAltEmpty = regexp.MustCompile(`(?i)\balt=["']\s*["']`)
	reLang        = regexp.MustCompile(`<html[^>]+lang=["']([^"']*)["']`)
	reJSONLD      = regexp.MustCompile(`(?is)<script[^>]+type=["']application/ld\+json["'][^>]*>(.*?)</script>`)
	reSchemaType  = regexp.MustCompile(`"@type"\s*:\s*"([^"]+)"`)
	reStripTags   = regexp.MustCompile(`<[^>]*>`)

	rePreload            = regexp.MustCompile(`<link[^>]+rel=["']preload["']`)
	rePreconnect         = regexp.MustCompile(`<link[^>]+rel=["']preconnect["']`)
	reLazyImg            = regexp.MustCompile(`<img[^>]+loading=["']lazy["']`)
	reInlineScript       = regexp.MustCompile(`<script[^>]*>(?:[^<]|\n)+</script>`)
	reExternalScript     = regexp.MustCompile(`<script[^>]+src=["']`)
	reInlineStyle        = regexp.MustCompile(`<style[^>]*>`)
	reExternalStylesheet = regexp.MustCompile(`<link[^>]+rel=["']stylesheet["']`)
)

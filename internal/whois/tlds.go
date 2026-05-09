package whois

import (
	"regexp"
	"strings"
)

// tldConfig holds per-TLD overrides for WHOIS lookups. All fields are optional.
type tldConfig struct {
	// server overrides the IANA-discovered WHOIS server. Empty = ask IANA.
	server string
	// queryFormat rewrites the wire query for servers with non-standard syntax.
	// Nil = send the domain as-is.
	queryFormat func(domain string) string
	// normalize rewrites a raw response into the generic "key: value" form
	// the parser expects. Nil = pass through unchanged.
	normalize func(raw string) string
	// extensionKeys maps a lowercase WHOIS key (as produced by extractKeyValues)
	// to the display label stored in DomainInfo.Extensions. Nil = no extras.
	extensionKeys map[string]string
	// extensionSection is the section heading used when rendering Extensions.
	// Empty = use the default "Extensions".
	extensionSection string
}

// tlds is the single source of truth for TLD-specific WHOIS quirks.
var tlds = map[string]tldConfig{
	"com": {server: "whois.verisign-grs.com"},
	"net": {server: "whois.verisign-grs.com"},
	"org": {server: "whois.pir.org"},
	// DENIC returns only Domain + Status without the "-T dn" prefix.
	"de": {server: "whois.denic.de", queryFormat: func(d string) string { return "-T dn " + d }},
	// JPRS returns Japanese by default; "/e" requests English. The English
	// response uses bracketed labels (`[Domain Name]   value`) instead of
	// the conventional "key: value" form, so we rewrite it for the parser.
	"jp": {
		server:      "whois.jprs.jp",
		queryFormat: func(d string) string { return d + "/e" },
		normalize:   normalizeJPRS,
	},
	// .co.jp, .ne.jp, etc. all use the same JPRS server.
	// auDA returns standard key: value format; the three fields below describe
	// the registrant entity (the legal body holding the domain) and are distinct
	// from the contact-person fields (Registrant Contact Name, etc.).
	"au": {
		server:           "whois.auda.org.au",
		extensionSection: "Eligibility",
		// "eligibility type" is labelled "Type" rather than "Eligibility Type"
		// because labelWidth=14 would truncate the longer form; the section
		// heading already provides the "Eligibility" context.
		extensionKeys: map[string]string{
			"registrant":       "Registrant",
			"registrant id":    "Registrant ID",
			"eligibility type": "Type",
		},
	},
}

// Normalize applies any TLD-specific transformation that brings the raw
// response in line with the generic "key: value" parser. Unknown TLDs and
// TLDs without a normalizer pass through unchanged.
func Normalize(domain, raw string) string {
	cfg, ok := tlds[tldOf(domain)]
	if !ok || cfg.normalize == nil {
		return raw
	}
	return cfg.normalize(raw)
}

func tldOf(domain string) string {
	parts := strings.Split(domain, ".")
	return strings.ToLower(parts[len(parts)-1])
}

// jprsLabelLine matches a JPRS English-format data line:
//
//	a. [Domain Name]                GOOGLE.CO.JP
//	[State]                         Connected (2027/03/31)
//
// The optional "a. " prefix is a JPRS field code. Banner lines like
// "[ JPRS database ... ]" don't match because the label cannot start with
// whitespace, and lines with no value after the closing bracket are skipped.
var jprsLabelLine = regexp.MustCompile(`^\s*(?:[a-z]\.\s+)?\[([^\s\]][^\]]*)\]\s+(\S.*)$`)

// jprsLabelRenames maps JPRS-specific label names to the canonical key the
// generic parser already understands. Only labels that don't already match
// a generic name need to appear here.
var jprsLabelRenames = map[string]string{
	"state": "Status", // JPRS uses "State" for domain lifecycle (Connected/...)
}

// extractExtensions returns TLD-specific key-value pairs from the parsed WHOIS
// key-value map. Returns nil if the TLD has no extension keys configured or
// none of the keys appear in the response.
func extractExtensions(domain string, kv map[string][]string) map[string]string {
	cfg, ok := tlds[tldOf(domain)]
	if !ok || len(cfg.extensionKeys) == 0 {
		return nil
	}
	result := make(map[string]string)
	for kvKey, label := range cfg.extensionKeys {
		if vals := kv[kvKey]; len(vals) > 0 {
			result[label] = vals[0]
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// extensionSection returns the display heading for the extensions block.
// Falls back to "Extensions" when the TLD has no custom section name.
func extensionSection(domain string) string {
	if cfg, ok := tlds[tldOf(domain)]; ok && cfg.extensionSection != "" {
		return cfg.extensionSection
	}
	return "Extensions"
}

func normalizeJPRS(raw string) string {
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if m := jprsLabelLine.FindStringSubmatch(line); m != nil {
			label := strings.TrimSpace(m[1])
			if rename, ok := jprsLabelRenames[strings.ToLower(label)]; ok {
				label = rename
			}
			b.WriteString(label)
			b.WriteString(": ")
			b.WriteString(strings.TrimSpace(m[2]))
			b.WriteByte('\n')
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

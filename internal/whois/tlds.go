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

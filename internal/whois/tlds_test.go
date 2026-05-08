package whois

import (
	"strings"
	"testing"
)

func TestTLDQueryFormat(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"example.de", "-T dn example.de"}, // DENIC requires -T dn
		{"google.co.jp", "google.co.jp/e"}, // JPRS needs /e for English
		{"example.com", "example.com"},     // .com has no queryFormat override
		{"example.invalidtld", "example.invalidtld"},
	}
	for _, tt := range tests {
		cfg, ok := tlds[tldOf(tt.domain)]
		var got string
		if ok && cfg.queryFormat != nil {
			got = cfg.queryFormat(tt.domain)
		} else {
			got = tt.domain
		}
		if got != tt.want {
			t.Errorf("queryFormat(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}

func TestTLDServerOverrides(t *testing.T) {
	tests := map[string]string{
		"example.com":  "whois.verisign-grs.com",
		"example.net":  "whois.verisign-grs.com",
		"example.org":  "whois.pir.org",
		"example.de":   "whois.denic.de",
		"google.co.jp": "whois.jprs.jp",
	}
	for domain, want := range tests {
		cfg, ok := tlds[tldOf(domain)]
		if !ok || cfg.server != want {
			t.Errorf("tlds[%q].server = %q, want %q", tldOf(domain), cfg.server, want)
		}
	}
}

func TestNormalize_PassThroughForUnknownTLD(t *testing.T) {
	raw := "Domain Name: example.com\n"
	got := Normalize("example.com", raw)
	if got != raw {
		t.Errorf("Normalize() modified .com response (should pass through)")
	}
}

func TestNormalizeJPRS(t *testing.T) {
	raw := `[ JPRS database provides information on network administration. ]
[ Banner text continues here.                                  ]
Domain Information:
a. [Domain Name]                GOOGLE.CO.JP
g. [Organization]               Google Japan G.K.
p. [Name Server]                ns1.google.com
p. [Name Server]                ns2.google.com
s. [Signing Key]
[State]                         Connected (2027/03/31)
[Registered Date]               2001/03/22
[Last Update]                   2026/04/01 01:02:00 (JST)`

	out := normalizeJPRS(raw)

	mustContain := []string{
		"Domain Name: GOOGLE.CO.JP",
		"Name Server: ns1.google.com",
		"Name Server: ns2.google.com",
		"Status: Connected (2027/03/31)", // [State] renamed to Status
		"Registered Date: 2001/03/22",
		"Last Update: 2026/04/01 01:02:00 (JST)",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("normalized output missing %q\n--- output ---\n%s", s, out)
		}
	}
	// Banner [ ... ] lines must NOT be turned into key:value pairs.
	if strings.Contains(out, "JPRS database") && strings.Contains(out, "JPRS database:") {
		t.Errorf("banner line was rewritten as a key: value pair")
	}
	// Empty-value lines like "[Signing Key]" must be skipped, not produce "Signing Key: ".
	if strings.Contains(out, "Signing Key:") {
		t.Errorf("empty-value line was emitted")
	}

	// Round-trip through Parse to make sure the renamed fields get picked up.
	info := Parse(out)
	if len(info.Status) == 0 || info.Status[0] != "Connected (2027/03/31)" {
		t.Errorf("Parse(normalized).Status = %v, want [Connected (2027/03/31)]", info.Status)
	}
	if info.CreatedDate.Year() != 2001 {
		t.Errorf("Parse(normalized).CreatedDate year = %d, want 2001", info.CreatedDate.Year())
	}
	if info.UpdatedDate.Year() != 2026 {
		t.Errorf("Parse(normalized).UpdatedDate year = %d, want 2026", info.UpdatedDate.Year())
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Parse(normalized).Nameservers count = %d, want 2", len(info.Nameservers))
	}
}

func TestAUExtensions(t *testing.T) {
	raw := `Domain Name: auda.org.au
Last Modified: 2023-07-05T00:23:15Z
Registrar Name: auDA
Status: serverDeleteProhibited https://identitydigital.au/whois-status-codes#serverDeleteProhibited
Registrant Contact ID: 5b8528848e1b48ddbf62fa592f627c57-AU
Registrant Contact Name: CEO
Tech Contact ID: 5b8528848e1b48ddbf62fa592f627c57-AU
Tech Contact Name: CEO
Name Server: ingrid.ns.cloudflare.com
Name Server: karl.ns.cloudflare.com
DNSSEC: signedDelegation
Registrant: .au Domain Administration Ltd
Registrant ID: ACN 079 009 340
Eligibility Type: Company`

	info := Parse(raw)

	// Standard fields must still work.
	if info.Registrar != "auDA" {
		t.Errorf("Registrar = %q, want auDA", info.Registrar)
	}
	if info.UpdatedDate.Year() != 2023 {
		t.Errorf("UpdatedDate year = %d, want 2023", info.UpdatedDate.Year())
	}
	if len(info.Status) != 1 || info.Status[0] != "serverDeleteProhibited" {
		t.Errorf("Status = %v, want [serverDeleteProhibited]", info.Status)
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count = %d, want 2", len(info.Nameservers))
	}
	if !info.DNSSEC {
		t.Error("DNSSEC should be true for signedDelegation")
	}

	// Contact person fields must not be overwritten by the entity fields.
	var regName, techName string
	for _, c := range info.Contacts {
		switch c.Role {
		case "registrant":
			regName = c.Name
		case "tech":
			techName = c.Name
		}
	}
	if regName != "CEO" {
		t.Errorf("registrant contact name = %q, want CEO", regName)
	}
	if techName != "CEO" {
		t.Errorf("tech contact name = %q, want CEO", techName)
	}

	// Entity extensions must be captured.
	if got := info.Extensions["Registrant"]; got != ".au Domain Administration Ltd" {
		t.Errorf("Extensions[Registrant] = %q, want .au Domain Administration Ltd", got)
	}
	if got := info.Extensions["Registrant ID"]; got != "ACN 079 009 340" {
		t.Errorf("Extensions[Registrant ID] = %q, want ACN 079 009 340", got)
	}
	if got := info.Extensions["Type"]; got != "Company" {
		t.Errorf("Extensions[Type] = %q, want Company", got)
	}
}

func TestCleanReferralHost(t *testing.T) {
	tests := map[string]string{
		// Bare hostname — unchanged.
		"whois.markmonitor.com": "whois.markmonitor.com",
		// Standard schemes.
		"http://whois.markmonitor.com":  "whois.markmonitor.com",
		"https://whois.markmonitor.com": "whois.markmonitor.com",
		// Mixed-case scheme (RFC says scheme is case-insensitive).
		"HTTPS://whois.markmonitor.com": "whois.markmonitor.com",
		"Http://whois.example.com":      "whois.example.com",
		// Whitespace.
		"  whois.example.com  ": "whois.example.com",
		// Path / query / fragment.
		"https://whois.example.com/path":    "whois.example.com",
		"https://whois.example.com/p?q=1":   "whois.example.com",
		"https://whois.example.com#section": "whois.example.com",
		"  https://whois.example.com/path ": "whois.example.com",
		// Explicit :port — must be stripped, otherwise JoinHostPort double-ports.
		"whois.example.com:43":         "whois.example.com",
		"whois.example.com:4343":       "whois.example.com",
		"https://whois.example.com:43": "whois.example.com",
		"http://whois.example.com:43/": "whois.example.com",
		// Empty.
		"": "",
	}
	for in, want := range tests {
		if got := cleanReferralHost(in); got != want {
			t.Errorf("cleanReferralHost(%q) = %q, want %q", in, got, want)
		}
	}
}

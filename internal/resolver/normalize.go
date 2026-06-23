package resolver

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// idnaProfile parses and validates domains under the IDNA2008 "lookup" rules,
// mapping case/width and enforcing the Bidi rule before converting to ASCII.
var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.Transitional(false))

// toASCII converts a domain to its ASCII (punycode) form, returning an error
// for input that isn't a valid domain under IDNA lookup rules.
func toASCII(s string) (string, error) {
	return idnaProfile.ToASCII(s)
}

// NormalizeDomain trims surrounding whitespace and a trailing dot from s and
// returns its lowercased ASCII (punycode) form. IP literals pass through
// unchanged — they aren't domains and IDNA rejects the colons in IPv6 — while
// any other input that isn't a valid domain under IDNA lookup rules yields an
// error so callers can reject it instead of dispatching a doomed lookup.
func NormalizeDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if net.ParseIP(s) != nil {
		return strings.ToLower(s), nil
	}
	ascii, err := toASCII(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid domain", s)
	}
	return ascii, nil
}

// RegistrableDomain returns the effective TLD+1 for s — the registrable
// domain that a WHOIS/RDAP registry will actually answer queries for.
// For "mail.google.com" it returns "google.com"; for "sub.example.co.jp" it
// returns "example.co.jp"; for "example.com" it returns "example.com".
//
// Inputs that clearly aren't domains ("hello", "version", bare suffixes like
// "co.jp", anything without a dot) return an error so callers can reject them
// cleanly instead of dispatching a doomed WHOIS query.
func RegistrableDomain(s string) (string, error) {
	ascii, err := toASCII(s)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid domain", s)
	}
	s = ascii
	if len(s) < 3 || len(s) > 253 {
		return "", fmt.Errorf("%q is not a valid domain", s)
	}
	if !strings.Contains(s, ".") {
		return "", fmt.Errorf("%q is not a valid domain", s)
	}
	suffix, icann := publicsuffix.PublicSuffix(s)
	if icann {
		d, err := publicsuffix.EffectiveTLDPlusOne(s)
		if err != nil {
			return "", fmt.Errorf("%q is not a valid domain", s)
		}
		return d, nil
	}
	// !icann means the matched suffix is either a private suffix
	// (e.g. github.io, netlify.app) or the fallback single-label rule for
	// unknown TLDs. A multi-label private suffix is itself the registrable
	// domain — that's what the domain owner actually registered at the
	// ICANN registry. A single-label !icann match (e.g. "bar" from foo.bar)
	// means we don't recognize the TLD and should reject.
	if strings.Contains(suffix, ".") {
		return suffix, nil
	}
	return "", fmt.Errorf("%q is not a valid domain", s)
}

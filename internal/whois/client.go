package whois

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	defaultPort    = "43"
	connectTimeout = 10 * time.Second
	readTimeout    = 10 * time.Second
)

// Query performs a raw WHOIS lookup for the given domain, applying any
// TLD-specific server and query-format overrides from tlds.go.
func Query(domain string) (string, error) {
	server := Server(domain)
	wire := domain
	if cfg, ok := tlds[tldOf(domain)]; ok && cfg.queryFormat != nil {
		wire = cfg.queryFormat(domain)
	}
	return queryRaw(server, wire)
}

// QueryServer performs a WHOIS lookup against a specific server, sending
// the domain as-is. Used for IANA discovery and referral follow-ups, where
// TLD-specific query rewriting does not apply.
func QueryServer(domain, server string) (string, error) {
	return queryRaw(server, domain)
}

func queryRaw(server, wire string) (string, error) {
	addr := net.JoinHostPort(server, defaultPort)

	conn, err := net.DialTimeout("tcp", addr, connectTimeout)
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", server, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

	_, err = fmt.Fprintf(conn, "%s\r\n", wire)
	if err != nil {
		return "", fmt.Errorf("sending query: %w", err)
	}

	resp, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	return string(resp), nil
}

// QueryWithReferral queries WHOIS and follows a single referral if present.
func QueryWithReferral(domain string) (string, error) {
	resp, err := Query(domain)
	if err != nil {
		return "", err
	}

	referral := extractReferral(resp)
	if referral == "" {
		return resp, nil
	}

	// Don't follow referral to the same server we just queried
	currentServer := Server(domain)
	if strings.EqualFold(referral, currentServer) {
		return resp, nil
	}

	// Query the referral server for more detailed info
	detailed, err := QueryServer(domain, referral)
	if err != nil {
		return resp, nil
	}

	// If the referral response looks empty/useless, keep the original
	if LooksEmpty(detailed) {
		return resp, nil
	}

	return detailed, nil
}

// LooksEmpty checks if a WHOIS response has no useful domain data.
func LooksEmpty(resp string) bool {
	lower := strings.ToLower(resp)
	if strings.Contains(lower, "does not exist") ||
		strings.Contains(lower, "no match") ||
		strings.Contains(lower, "not found") ||
		strings.Contains(lower, "no entries found") ||
		strings.Contains(lower, "no data found") ||
		strings.Contains(lower, "no object found") ||
		strings.Contains(lower, "status: free") {
		return true
	}
	// Check if there's at least one key: value pair with domain info
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		l := strings.ToLower(line)
		if strings.HasPrefix(l, "domain name:") ||
			strings.HasPrefix(l, "domain:") ||
			strings.HasPrefix(l, "creation date:") ||
			strings.HasPrefix(l, "created:") ||
			strings.HasPrefix(l, "updated date:") ||
			strings.HasPrefix(l, "last update:") ||
			strings.HasPrefix(l, "expiry date:") ||
			strings.HasPrefix(l, "expire date:") ||
			strings.HasPrefix(l, "registrar:") ||
			strings.HasPrefix(l, "status:") ||
			strings.HasPrefix(l, "domain status:") ||
			strings.HasPrefix(l, "name server:") ||
			strings.HasPrefix(l, "nameserver:") {
			return false
		}
	}
	return true
}

func extractReferral(resp string) string {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "registrar whois server:") ||
			strings.HasPrefix(lower, "whois server:") ||
			strings.HasPrefix(lower, "refer:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if server := cleanReferralHost(parts[1]); server != "" {
					return server
				}
			}
		}
	}
	return ""
}

// cleanReferralHost normalizes a referral value into a bare hostname suitable
// for dialing on port 43. Handles case-insensitive schemes, paths/queries, and
// explicit :port suffixes (which would otherwise double-port via JoinHostPort).
// WHOIS is always port 43 in practice, so any explicit port is discarded.
func cleanReferralHost(s string) string {
	s = strings.TrimSpace(s)
	// Strip scheme (case-insensitive), e.g. "HTTPS://".
	if i := strings.Index(strings.ToLower(s), "://"); i != -1 && i < 10 {
		s = s[i+3:]
	}
	// Strip path, query, fragment, or trailing whitespace.
	if i := strings.IndexAny(s, "/?# "); i != -1 {
		s = s[:i]
	}
	// Strip explicit ":port" (hostnames cannot contain ':', and WHOIS
	// referrals never use IPv6 literals).
	if i := strings.Index(s, ":"); i != -1 {
		s = s[:i]
	}
	return s
}

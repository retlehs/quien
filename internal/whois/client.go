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

// Query performs a raw WHOIS lookup for the given domain.
func Query(domain string) (string, error) {
	server := Server(domain)
	return QueryServer(domain, server)
}

// QueryServer performs a WHOIS lookup against a specific server.
func QueryServer(domain, server string) (string, error) {
	addr := net.JoinHostPort(server, defaultPort)

	conn, err := net.DialTimeout("tcp", addr, connectTimeout)
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", server, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

	_, err = fmt.Fprintf(conn, "%s\r\n", domain)
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
				server := strings.TrimSpace(parts[1])
				if server != "" {
					return server
				}
			}
		}
	}
	return ""
}

package dnsutil

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	mdns "github.com/miekg/dns"
)

const ResolverEnvVar = "QUIEN_RESOLVER"

// NormalizeResolver converts a resolver string into host:port form.
// Accepted input forms are host, host:port, IPv4, IPv4:port, IPv6, [IPv6]:port.
func NormalizeResolver(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("resolver is empty")
	}

	if host, port, err := net.SplitHostPort(s); err == nil {
		if host == "" {
			return "", fmt.Errorf("resolver host is empty")
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("resolver port must be between 1 and 65535")
		}
		return net.JoinHostPort(host, strconv.Itoa(p)), nil
	}

	if strings.Count(s, ":") > 1 && net.ParseIP(s) == nil {
		return "", fmt.Errorf("invalid resolver %q", s)
	}

	return net.JoinHostPort(s, "53"), nil
}

// ResolverFromEnv returns the normalized resolver from QUIEN_RESOLVER.
// Empty string means not set or invalid.
func ResolverFromEnv() string {
	raw := strings.TrimSpace(os.Getenv(ResolverEnvVar))
	if raw == "" {
		return ""
	}
	resolver, err := NormalizeResolver(raw)
	if err != nil {
		return ""
	}
	return resolver
}

// FindResolver returns resolver from env override, /etc/resolv.conf, then fallback.
func FindResolver() string {
	if resolver := ResolverFromEnv(); resolver != "" {
		return resolver
	}

	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(config.Servers) > 0 {
		port := config.Port
		if p, pErr := strconv.Atoi(port); pErr != nil || p < 1 || p > 65535 {
			port = "53"
		}
		return net.JoinHostPort(config.Servers[0], port)
	}

	return "1.1.1.1:53"
}

package dnsutil

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

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

// resolvConfPaths are probed in order. systemd-resolved's stub at 127.0.0.53
// consults /etc/hosts, so prefer the file with the real upstream DNS servers
// when it exists.
var resolvConfPaths = []string{
	"/run/systemd/resolve/resolv.conf",
	"/etc/resolv.conf",
}

// FindResolver returns resolver from env override, resolv.conf, then fallback.
func FindResolver() string {
	if resolver := ResolverFromEnv(); resolver != "" {
		return resolver
	}
	if resolver := resolverFromFiles(resolvConfPaths); resolver != "" {
		return resolver
	}
	return "1.1.1.1:53"
}

// resolverFromFiles returns the first non-loopback nameserver found across the
// given resolv.conf-style files. Loopback nameservers are skipped because
// they're typically stub resolvers (e.g. systemd-resolved) that honor
// /etc/hosts, which defeats the purpose of querying authoritative DNS for a
// public domain.
func resolverFromFiles(paths []string) string {
	for _, path := range paths {
		config, err := mdns.ClientConfigFromFile(path)
		if err != nil {
			continue
		}
		port := config.Port
		if p, pErr := strconv.Atoi(port); pErr != nil || p < 1 || p > 65535 {
			port = "53"
		}
		for _, server := range config.Servers {
			ip := net.ParseIP(server)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			return net.JoinHostPort(server, port)
		}
	}
	return ""
}

// GoResolver returns a net.Resolver that bypasses local NSS/files and dials the
// configured DNS server directly.
func GoResolver(timeout time.Duration) *net.Resolver {
	target := FindResolver()
	dialer := &net.Dialer{Timeout: timeout}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if strings.HasPrefix(network, "tcp") {
				return dialer.DialContext(ctx, "tcp", target)
			}
			return dialer.DialContext(ctx, "udp", target)
		},
	}
}

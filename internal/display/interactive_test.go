package display

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/retlehs/quien/internal/dns"
)

func TestResolveFirstIPValuePrefersCachedDNSRecords(t *testing.T) {
	t.Parallel()

	ip, err := resolveFirstIPValue("example.com", &dns.Records{
		A: []string{"93.184.216.34"},
	}, ipLookupDeps{
		lookupDNSIPs: func(domain string) ([]string, []string, error) {
			return []string{"127.0.1.1"}, nil, nil
		},
		lookupIPAddr: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.1.1")}}, nil
		},
	})
	if err != nil {
		t.Fatalf("resolveFirstIPValue() error = %v", err)
	}
	if ip != "93.184.216.34" {
		t.Fatalf("resolveFirstIPValue() = %q, want %q", ip, "93.184.216.34")
	}
}

func TestResolveFirstIPValueUsesCachedAAAAWhenAIsMissing(t *testing.T) {
	t.Parallel()

	ip, err := resolveFirstIPValue("example.com", &dns.Records{
		AAAA: []string{"2001:db8::44"},
	}, ipLookupDeps{
		lookupDNSIPs: func(domain string) ([]string, []string, error) {
			return []string{"198.51.100.11"}, nil, nil
		},
		lookupIPAddr: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.1.1")}}, nil
		},
	})
	if err != nil {
		t.Fatalf("resolveFirstIPValue() error = %v", err)
	}
	if ip != "2001:db8::44" {
		t.Fatalf("resolveFirstIPValue() = %q, want %q", ip, "2001:db8::44")
	}
}

func TestResolveFirstIPValueCachedEmptyUsesDNSLookup(t *testing.T) {
	t.Parallel()

	lookupDNSCalled := false
	ip, err := resolveFirstIPValue("example.com", &dns.Records{}, ipLookupDeps{
		lookupDNSIPs: func(domain string) ([]string, []string, error) {
			lookupDNSCalled = true
			return []string{"198.51.100.22"}, nil, nil
		},
		lookupIPAddr: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			t.Fatalf("unexpected fallback lookup call")
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("resolveFirstIPValue() error = %v", err)
	}
	if !lookupDNSCalled {
		t.Fatalf("expected DNS lookup to be called")
	}
	if ip != "198.51.100.22" {
		t.Fatalf("resolveFirstIPValue() = %q, want %q", ip, "198.51.100.22")
	}
}

func TestResolveFirstIPValueFallsBackToConfiguredResolver(t *testing.T) {
	t.Parallel()

	ip, err := resolveFirstIPValue("example.com", nil, ipLookupDeps{
		lookupDNSIPs: func(domain string) ([]string, []string, error) {
			return nil, nil, fmt.Errorf("dns failed")
		},
		lookupIPAddr: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{
				{IP: net.ParseIP("2001:db8::1")},
				{IP: net.ParseIP("198.51.100.7")},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("resolveFirstIPValue() error = %v", err)
	}
	if ip != "198.51.100.7" {
		t.Fatalf("resolveFirstIPValue() = %q, want %q", ip, "198.51.100.7")
	}
}

func TestResolveFirstIPValueUsesAAAAWhenANotPresent(t *testing.T) {
	t.Parallel()

	ip, err := resolveFirstIPValue("example.com", nil, ipLookupDeps{
		lookupDNSIPs: func(domain string) ([]string, []string, error) {
			return nil, []string{"2001:db8::2"}, nil
		},
		lookupIPAddr: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.1.1")}}, nil
		},
	})
	if err != nil {
		t.Fatalf("resolveFirstIPValue() error = %v", err)
	}
	if ip != "2001:db8::2" {
		t.Fatalf("resolveFirstIPValue() = %q, want %q", ip, "2001:db8::2")
	}
}

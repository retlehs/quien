package display

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/retlehs/quien/internal/dns"
	"github.com/retlehs/quien/internal/security"
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

func TestRenderSecurityNotFound(t *testing.T) {
	t.Parallel()

	result := &security.Result{Found: false}
	output := RenderSecurity(result)

	if !strings.Contains(output, "No security.txt found") {
		t.Fatalf("expected 'No security.txt found', got:\n%s", output)
	}
}

func TestRenderSecurityFoundWithFields(t *testing.T) {
	t.Parallel()

	result := &security.Result{
		Found:      true,
		URL:        "https://example.com/.well-known/security.txt",
		StatusCode: 200,
		Content:    "Contact: mailto:security@example.com\nPolicy: https://example.com/policy\n",
		Fields: map[string][]string{
			"contact": {"mailto:security@example.com"},
			"policy":  {"https://example.com/policy"},
		},
	}
	output := RenderSecurity(result)

	if !strings.Contains(output, "security.txt") {
		t.Fatal("expected title 'security.txt'")
	}
	if !strings.Contains(output, "Location") {
		t.Fatal("expected section 'Location'")
	}
	if !strings.Contains(output, "example.com/.well-known/security.txt") {
		t.Fatal("expected URL in output")
	}
	if !strings.Contains(output, "Fields") {
		t.Fatal("expected section 'Fields'")
	}
	if !strings.Contains(output, "mailto:security@example.com") {
		t.Fatal("expected contact value in output")
	}
	if !strings.Contains(output, "Raw Content") {
		t.Fatal("expected section 'Raw Content'")
	}
}

func TestRenderSecurityFoundNoFields(t *testing.T) {
	t.Parallel()

	result := &security.Result{
		Found:   true,
		URL:     "https://example.com/.well-known/security.txt",
		Content: "# just a comment\n\n",
		Fields:  map[string][]string{},
	}
	output := RenderSecurity(result)

	if !strings.Contains(output, "security.txt") {
		t.Fatal("expected title 'security.txt'")
	}
	if !strings.Contains(output, "Raw Content") {
		t.Fatal("expected section 'Raw Content'")
	}
}

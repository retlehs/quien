package display

import (
	"strings"
	"testing"

	"github.com/retlehs/quien/internal/dns"
	"github.com/retlehs/quien/internal/dnsutil"
)

func TestRenderHTTPSRecord(t *testing.T) {
	tests := []struct {
		name    string
		record  dns.HTTPSRecord
		want    []string // substrings expected in the output
		notWant []string
	}{
		{
			name: "service mode self target shows priority and self",
			record: dns.HTTPSRecord{
				Priority:  1,
				Target:    ".",
				ALPN:      []string{"h3", "h2"},
				IPv4Hint:  []string{"104.16.132.229"},
				ECHConfig: "AAE=",
			},
			want: []string{"(self)", "(1)", "alpn", "h3, h2", "ipv4hint", "104.16.132.229", "ech", "present"},
		},
		{
			name:    "alias mode shows target",
			record:  dns.HTTPSRecord{Priority: 0, Target: "svc.example.net"},
			want:    []string{"alias", "svc.example.net"},
			notWant: []string{"alpn", "(self)"},
		},
		{
			name:   "service mode named target shows target and priority",
			record: dns.HTTPSRecord{Priority: 16, Target: "svc.example.net", Port: 8443},
			want:   []string{"svc.example.net", "(16)", "port", "8443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderHTTPSRecord(tt.record)
			for _, sub := range tt.want {
				if !strings.Contains(got, sub) {
					t.Errorf("output missing %q\ngot:\n%s", sub, got)
				}
			}
			for _, sub := range tt.notWant {
				if strings.Contains(got, sub) {
					t.Errorf("output unexpectedly contains %q\ngot:\n%s", sub, got)
				}
			}
		})
	}
}

func TestRenderDNSNSResolution(t *testing.T) {
	records := &dns.Records{NS: []string{"ns1.example.com", "ns2.example.com"}}
	resolutions := []dnsutil.HostResolution{
		{Host: "ns1.example.com", IPs: []dnsutil.HostIP{
			{IP: "192.0.2.1", PTRs: []string{"a.example.com", "b.example.com"}},
		}},
		{Host: "ns2.example.com", Err: "no such host"},
	}

	out := RenderDNS(records, resolutions)

	for _, want := range []string{"192.0.2.1", "a.example.com", "b.example.com", "no such host"} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderDNS output missing %q\n%s", want, out)
		}
	}
}

func TestRenderDNSWithoutResolution(t *testing.T) {
	// Passing no resolutions renders the bare NS list (default behavior).
	records := &dns.Records{NS: []string{"ns1.example.com"}}
	out := RenderDNS(records, nil)
	if !strings.Contains(out, "ns1.example.com") {
		t.Errorf("RenderDNS output missing NS host\n%s", out)
	}
	if strings.Contains(out, "192.0.2") {
		t.Errorf("RenderDNS rendered resolved IPs without resolutions\n%s", out)
	}
}

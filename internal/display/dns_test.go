package display

import (
	"strings"
	"testing"

	"github.com/retlehs/quien/internal/dns"
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

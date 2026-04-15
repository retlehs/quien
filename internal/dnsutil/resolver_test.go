package dnsutil

import "testing"

func TestNormalizeResolver(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "9.9.9.9", want: "9.9.9.9:53"},
		{in: "9.9.9.9:5353", want: "9.9.9.9:5353"},
		{in: "2001:4860:4860::8888", want: "[2001:4860:4860::8888]:53"},
		{in: "[2001:4860:4860::8888]:5353", want: "[2001:4860:4860::8888]:5353"},
		{in: "example.com", want: "example.com:53"},
		{in: "1.1.1.1:70000", wantErr: true},
	}

	for _, tt := range tests {
		got, err := NormalizeResolver(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("NormalizeResolver(%q) expected error, got %q", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizeResolver(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeResolver(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

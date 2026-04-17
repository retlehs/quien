package dnsutil

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestResolverFromFiles(t *testing.T) {
	dir := t.TempDir()

	stub := filepath.Join(dir, "stub-resolv.conf")
	if err := os.WriteFile(stub, []byte("nameserver 127.0.0.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	upstream := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(upstream, []byte("nameserver 1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	mixed := filepath.Join(dir, "mixed-resolv.conf")
	if err := os.WriteFile(mixed, []byte("nameserver 127.0.0.1\nnameserver 8.8.8.8\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	missing := filepath.Join(dir, "does-not-exist.conf")

	tests := []struct {
		name  string
		paths []string
		want  string
	}{
		{name: "prefers first non-loopback file", paths: []string{upstream, stub}, want: "1.1.1.1:53"},
		{name: "skips loopback-only file", paths: []string{stub, upstream}, want: "1.1.1.1:53"},
		{name: "skips missing file", paths: []string{missing, upstream}, want: "1.1.1.1:53"},
		{name: "skips loopback server within file", paths: []string{mixed}, want: "8.8.8.8:53"},
		{name: "returns empty when all loopback", paths: []string{stub}, want: ""},
		{name: "returns empty when no files readable", paths: []string{missing}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolverFromFiles(tt.paths)
			if got != tt.want {
				t.Fatalf("resolverFromFiles(%v) = %q, want %q", tt.paths, got, tt.want)
			}
		})
	}
}

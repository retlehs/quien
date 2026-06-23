package dnsutil

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
)

type fakeResolver struct {
	ips    map[string][]net.IPAddr
	ipErr  map[string]error
	ptrs   map[string][]string
	ptrErr map[string]error
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if err := f.ipErr[host]; err != nil {
		return nil, err
	}
	return f.ips[host], nil
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if err := f.ptrErr[addr]; err != nil {
		return nil, err
	}
	return f.ptrs[addr], nil
}

func ipAddrs(ips ...string) []net.IPAddr {
	out := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		out[i] = net.IPAddr{IP: net.ParseIP(ip)}
	}
	return out
}

func TestResolveHosts(t *testing.T) {
	r := fakeResolver{
		ips: map[string][]net.IPAddr{
			"ns1.example.com":   ipAddrs("192.0.2.1", "2001:db8::1"),
			"ns2.example.com":   ipAddrs("192.0.2.2"),
			"noptr.example.com": ipAddrs("192.0.2.9"),
		},
		ptrs: map[string][]string{
			// Two PTRs for one address, with trailing dots to be trimmed.
			"192.0.2.1":   {"a.example.com.", "b.example.com."},
			"2001:db8::1": {"v6.example.com."},
			"192.0.2.2":   {"ns2.example.com."},
		},
		ipErr: map[string]error{
			"broken.example.com": errors.New("no such host"),
		},
		ptrErr: map[string]error{
			"192.0.2.9": errors.New("reverse failed"),
		},
	}

	hosts := []string{"ns1.example.com", "ns2.example.com", "broken.example.com", "noptr.example.com"}
	got := resolveHosts(hosts, r)

	// Order is preserved 1:1 with the input.
	if len(got) != len(hosts) {
		t.Fatalf("got %d resolutions, want %d", len(got), len(hosts))
	}
	for i, h := range hosts {
		if got[i].Host != h {
			t.Errorf("resolution[%d].Host = %q, want %q", i, got[i].Host, h)
		}
	}

	// Multiple IPs, and multiple PTRs per IP, with trailing dots trimmed.
	ns1 := got[0]
	if ns1.Err != "" {
		t.Errorf("ns1 unexpected Err: %q", ns1.Err)
	}
	want := []HostIP{
		{IP: "192.0.2.1", PTRs: []string{"a.example.com", "b.example.com"}},
		{IP: "2001:db8::1", PTRs: []string{"v6.example.com"}},
	}
	if !reflect.DeepEqual(ns1.IPs, want) {
		t.Errorf("ns1.IPs = %+v, want %+v", ns1.IPs, want)
	}

	// Forward-lookup failure records Err and no IPs.
	broken := got[2]
	if broken.Err == "" {
		t.Errorf("broken: expected Err to be set")
	}
	if len(broken.IPs) != 0 {
		t.Errorf("broken: expected no IPs, got %+v", broken.IPs)
	}

	// Reverse-lookup failure leaves the IP present with no PTRs.
	noptr := got[3]
	if len(noptr.IPs) != 1 || noptr.IPs[0].IP != "192.0.2.9" {
		t.Fatalf("noptr.IPs = %+v, want single 192.0.2.9", noptr.IPs)
	}
	if len(noptr.IPs[0].PTRs) != 0 {
		t.Errorf("noptr PTRs = %v, want none", noptr.IPs[0].PTRs)
	}
}

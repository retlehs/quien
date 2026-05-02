package mail

import (
	"net"
	"reflect"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

// startTruncatingDNSServer spins up a local UDP+TCP DNS server that returns
// a truncated UDP response (TC flag set, empty answer) but a full answer
// over TCP. This simulates the real-world scenario where many TXT records
// exceed the 512-byte UDP limit.
func startTruncatingDNSServer(t *testing.T, domain, spfRecord string) string {
	t.Helper()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := udpConn.LocalAddr().String()

	tcpLn, err := net.Listen("tcp", udpAddr)
	if err != nil {
		_ = udpConn.Close()
		t.Fatal(err)
	}

	// TCP handler — returns all records.
	tcpHandler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == mdns.TypeTXT {
			m.Answer = append(m.Answer, &mdns.TXT{
				Hdr: mdns.RR_Header{Name: domain, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
				Txt: []string{spfRecord},
			})
		}
		_ = w.WriteMsg(m)
	})

	// UDP handler — always sets TC (truncated) flag with an empty answer.
	udpHandler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})

	tcpServer := &mdns.Server{Listener: tcpLn, Handler: tcpHandler, Net: "tcp"}
	udpServer := &mdns.Server{PacketConn: udpConn, Handler: udpHandler, Net: "udp"}

	go func() { _ = tcpServer.ActivateAndServe() }()
	go func() { _ = udpServer.ActivateAndServe() }()

	t.Cleanup(func() {
		_ = tcpServer.Shutdown()
		_ = udpServer.Shutdown()
	})

	return udpAddr
}

func TestQueryTCPFallbackOnTruncation(t *testing.T) {
	domain := "example.com."
	spf := "v=spf1 include:_spf.google.com ~all"
	resolver := startTruncatingDNSServer(t, domain, spf)

	rr, err := query(domain, mdns.TypeTXT, resolver)
	if err != nil {
		t.Fatalf("query returned error: %v", err)
	}

	var found string
	for _, r := range rr {
		if txt, ok := r.(*mdns.TXT); ok {
			for _, s := range txt.Txt {
				if s == spf {
					found = s
				}
			}
		}
	}

	if found == "" {
		t.Errorf("expected SPF record %q in TCP response, got none", spf)
	}
}

func TestMergeDKIMSelectors(t *testing.T) {
	tests := []struct {
		name     string
		user     []string
		defaults []string
		want     []string
	}{
		{
			name:     "no user selectors keeps defaults in order",
			defaults: []string{"default", "google", "selector1"},
			want:     []string{"default", "google", "selector1"},
		},
		{
			name:     "user selectors come first",
			user:     []string{"foo", "bar"},
			defaults: []string{"default", "google"},
			want:     []string{"foo", "bar", "default", "google"},
		},
		{
			name:     "dedupes case-insensitively, preserving user spelling",
			user:     []string{"Google", "custom"},
			defaults: []string{"default", "google"},
			want:     []string{"Google", "custom", "default"},
		},
		{
			name:     "trims whitespace and drops empty entries",
			user:     []string{"  foo  ", "", "   "},
			defaults: []string{"default"},
			want:     []string{"foo", "default"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeDKIMSelectors(tc.user, tc.defaults)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("mergeDKIMSelectors(%v, %v) = %v, want %v", tc.user, tc.defaults, got, tc.want)
			}
		})
	}
}

// startDKIMServer spins up a UDP DNS server that returns a v=DKIM1 TXT record
// for each selector in records, and NXDOMAIN otherwise.
func startDKIMServer(t *testing.T, domain string, records map[string]string) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		suffix := "._domainkey." + domain + "."
		if q.Qtype == mdns.TypeTXT && strings.HasSuffix(q.Name, suffix) {
			sel := strings.TrimSuffix(q.Name, suffix)
			if val, ok := records[sel]; ok {
				m.Answer = append(m.Answer, &mdns.TXT{
					Hdr: mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
					Txt: []string{val},
				})
			} else {
				m.Rcode = mdns.RcodeNameError
			}
		}
		_ = w.WriteMsg(m)
	})

	server := &mdns.Server{PacketConn: conn, Handler: handler, Net: "udp"}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	return conn.LocalAddr().String()
}

func TestLookupDKIMUserSelectorHit(t *testing.T) {
	domain := "example.com"
	resolver := startDKIMServer(t, domain, map[string]string{
		"custom": "v=DKIM1; k=rsa; p=PUBKEY",
	})

	got := lookupDKIM(domain, []string{"custom", "default"}, resolver)
	if len(got) != 1 {
		t.Fatalf("expected 1 DKIM record, got %d", len(got))
	}
	if got[0].Selector != "custom" {
		t.Errorf("selector: got %q, want %q", got[0].Selector, "custom")
	}
	if !strings.Contains(strings.ToLower(got[0].Value), "v=dkim1") {
		t.Errorf("value missing v=dkim1: %q", got[0].Value)
	}
}

func TestLookupDKIMPreservesSelectorOrder(t *testing.T) {
	domain := "example.com"
	resolver := startDKIMServer(t, domain, map[string]string{
		"google":  "v=DKIM1; k=rsa; p=A",
		"custom":  "v=DKIM1; k=rsa; p=B",
		"default": "v=DKIM1; k=rsa; p=C",
	})

	// Order: user-supplied "custom" first, then built-ins "default", "google".
	selectors := mergeDKIMSelectors([]string{"custom"}, []string{"default", "google"})
	got := lookupDKIM(domain, selectors, resolver)

	want := []string{"custom", "default", "google"}
	if len(got) != len(want) {
		t.Fatalf("expected %d records, got %d", len(want), len(got))
	}
	for i, sel := range want {
		if got[i].Selector != sel {
			t.Errorf("position %d: got %q, want %q", i, got[i].Selector, sel)
		}
	}
}

func TestSelectorsFromEnv(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want []string
	}{
		{name: "unset", env: "", want: nil},
		{name: "single value", env: "foo", want: []string{"foo"}},
		{name: "comma separated", env: "foo,bar,baz", want: []string{"foo", "bar", "baz"}},
		{name: "trims whitespace and drops empties", env: " foo , , bar ,", want: []string{"foo", "bar"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(DKIMSelectorsEnvVar, tc.env)
			got := selectorsFromEnv()
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("selectorsFromEnv() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLookupDKIMSkipsNonDKIMTXT(t *testing.T) {
	domain := "example.com"
	resolver := startDKIMServer(t, domain, map[string]string{
		"foo": "not a dkim record",
		"bar": "v=DKIM1; k=rsa; p=PUBKEY",
	})

	got := lookupDKIM(domain, []string{"foo", "bar"}, resolver)
	if len(got) != 1 {
		t.Fatalf("expected 1 DKIM record, got %d", len(got))
	}
	if got[0].Selector != "bar" {
		t.Errorf("selector: got %q, want %q", got[0].Selector, "bar")
	}
}

func TestQueryUDPSuccessSkipsTCPFallback(t *testing.T) {
	domain := "small.example."
	spf := "v=spf1 -all"

	// Server that returns a full answer over UDP (no truncation).
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == mdns.TypeTXT {
			m.Answer = append(m.Answer, &mdns.TXT{
				Hdr: mdns.RR_Header{Name: domain, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
				Txt: []string{spf},
			})
		}
		_ = w.WriteMsg(m)
	})
	server := &mdns.Server{PacketConn: conn, Handler: handler, Net: "udp"}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	addr := conn.LocalAddr().String()
	rr, err := query(domain, mdns.TypeTXT, addr)
	if err != nil {
		t.Fatalf("query returned error: %v", err)
	}
	if len(rr) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(rr))
	}
}

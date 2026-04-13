package dns

import (
	"net"
	"testing"

	mdns "github.com/miekg/dns"
)

// startTruncatingDNSServer spins up a local UDP+TCP DNS server that returns
// a truncated UDP response (TC flag set, empty answer) but a full answer
// over TCP.
func startTruncatingDNSServer(t *testing.T, domain string, records []string) string {
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
			for _, rec := range records {
				m.Answer = append(m.Answer, &mdns.TXT{
					Hdr: mdns.RR_Header{Name: domain, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
					Txt: []string{rec},
				})
			}
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
	txtRecords := []string{
		"v=spf1 include:_spf.google.com ~all",
		"google-site-verification=abc123",
		"MS=ms12345",
	}
	resolver := startTruncatingDNSServer(t, domain, txtRecords)

	rr, err := query(domain, mdns.TypeTXT, resolver)
	if err != nil {
		t.Fatalf("query returned error: %v", err)
	}

	if len(rr) != len(txtRecords) {
		t.Errorf("expected %d TXT records, got %d", len(txtRecords), len(rr))
	}
}

func TestQueryUDPSuccessSkipsTCPFallback(t *testing.T) {
	domain := "small.example."
	txt := "v=spf1 -all"

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
				Txt: []string{txt},
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

func TestDecodeRNAME(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        string
		wantErr     bool
		errContains string
	}{
		{"simple name", "name.domain.com.", "name@domain.com", false, ""},
		{"escaped dots", "test\\.dot\\.period.domain.test.", "test.dot.period@domain.test", false, ""},
		{"escaped backslash before dot", "test\\\\.domain.com.", "test\\@domain.com", false, ""},
		{"missing @ separator", "nodotinname", "", true, "invalid RNAME: must contain both local-part and domain"},
		{"empty input", "", "", true, "invalid RNAME: must contain both local-part and domain"},
		{"single label", "singlelabel.", "", true, "invalid RNAME: must contain both local-part and domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRNAME(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeRNAME(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if err != nil && tt.errContains != "" && err.Error() != tt.errContains {
				t.Errorf("decodeRNAME(%q) error = %v, want error containing %q", tt.input, err, tt.errContains)
			}
			if got != tt.want {
				t.Errorf("decodeRNAME(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

package mail

import (
	"net"
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

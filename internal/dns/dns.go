package dns

import (
	"fmt"
	"sort"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/retlehs/quien/internal/dnsutil"
)

type Records struct {
	A      []string
	AAAA   []string
	CNAME  []string
	MX     []MXRecord
	NS     []string
	TXT    []string
	PTR    []PTRRecord
	SOA    *SOARecord
	DNSSEC bool
}

type PTRRecord struct {
	IP       string
	Hostname string
}

type MXRecord struct {
	Host     string
	Priority uint16
}

type SOARecord struct {
	PrimaryNS  string
	AdminEmail string
	Serial     uint32
	Refresh    uint32
	Retry      uint32
	Expire     uint32
	MinTTL     uint32
}

const timeout = 5 * time.Second

// Lookup queries common DNS record types for the given domain.
func Lookup(domain string) (*Records, error) {
	// Ensure domain has trailing dot for DNS queries
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	resolver := findResolver()
	records := &Records{}

	// Query each record type
	if rr, err := query(domain, mdns.TypeA, resolver); err == nil {
		for _, r := range rr {
			if a, ok := r.(*mdns.A); ok {
				records.A = append(records.A, a.A.String())
			}
		}
	}

	if rr, err := query(domain, mdns.TypeAAAA, resolver); err == nil {
		for _, r := range rr {
			if aaaa, ok := r.(*mdns.AAAA); ok {
				records.AAAA = append(records.AAAA, aaaa.AAAA.String())
			}
		}
	}

	if rr, err := query(domain, mdns.TypeCNAME, resolver); err == nil {
		for _, r := range rr {
			if cname, ok := r.(*mdns.CNAME); ok {
				records.CNAME = append(records.CNAME, strings.TrimSuffix(cname.Target, "."))
			}
		}
	}

	if rr, err := query(domain, mdns.TypeMX, resolver); err == nil {
		for _, r := range rr {
			if mx, ok := r.(*mdns.MX); ok {
				records.MX = append(records.MX, MXRecord{
					Host:     strings.TrimSuffix(mx.Mx, "."),
					Priority: mx.Preference,
				})
			}
		}
		sort.Slice(records.MX, func(i, j int) bool {
			return records.MX[i].Priority < records.MX[j].Priority
		})
	}

	if rr, err := query(domain, mdns.TypeNS, resolver); err == nil {
		for _, r := range rr {
			if ns, ok := r.(*mdns.NS); ok {
				records.NS = append(records.NS, strings.TrimSuffix(ns.Ns, "."))
			}
		}
		sort.Strings(records.NS)
	}

	if rr, err := query(domain, mdns.TypeTXT, resolver); err == nil {
		for _, r := range rr {
			if txt, ok := r.(*mdns.TXT); ok {
				records.TXT = append(records.TXT, strings.Join(txt.Txt, ""))
			}
		}
	}

	// PTR — reverse DNS for each A/AAAA record
	for _, ip := range records.A {
		if host := reverseLookup(ip, resolver); host != "" {
			records.PTR = append(records.PTR, PTRRecord{IP: ip, Hostname: host})
		}
	}
	for _, ip := range records.AAAA {
		if host := reverseLookup(ip, resolver); host != "" {
			records.PTR = append(records.PTR, PTRRecord{IP: ip, Hostname: host})
		}
	}

	if rr, err := query(domain, mdns.TypeSOA, resolver); err == nil {
		for _, r := range rr {
			if soa, ok := r.(*mdns.SOA); ok {
				admin, err := decodeRNAME(soa.Mbox)
				if err != nil {
					admin = strings.TrimSuffix(soa.Mbox, ".")
				}
				records.SOA = &SOARecord{
					PrimaryNS:  strings.TrimSuffix(soa.Ns, "."),
					AdminEmail: admin,
					Serial:     soa.Serial,
					Refresh:    soa.Refresh,
					Retry:      soa.Retry,
					Expire:     soa.Expire,
					MinTTL:     soa.Minttl,
				}
			}
		}
	}

	// DNSSEC — check for DNSKEY records
	if rr, err := query(domain, mdns.TypeDNSKEY, resolver); err == nil && len(rr) > 0 {
		records.DNSSEC = true
	}

	return records, nil
}

func query(domain string, qtype uint16, resolver string) ([]mdns.RR, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.RecursionDesired = true

	client := &mdns.Client{Timeout: timeout}
	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return nil, err
	}
	// Retry over TCP when the UDP response is truncated.
	if resp.Truncated {
		tcpClient := &mdns.Client{Timeout: timeout, Net: "tcp"}
		resp, _, err = tcpClient.Exchange(msg, resolver)
		if err != nil {
			return nil, err
		}
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed: %s", mdns.RcodeToString[resp.Rcode])
	}
	return resp.Answer, nil
}

func reverseLookup(ip string, resolver string) string {
	arpa, err := mdns.ReverseAddr(ip)
	if err != nil {
		return ""
	}
	if rr, err := query(arpa, mdns.TypePTR, resolver); err == nil {
		for _, r := range rr {
			if ptr, ok := r.(*mdns.PTR); ok {
				return strings.TrimSuffix(ptr.Ptr, ".")
			}
		}
	}
	return ""
}

func findResolver() string {
	return dnsutil.FindResolver()
}

// decodeRNAME decodes a DNS SOA RNAME field to its original mailbox format.
// The first unescaped dot separates the local-part from the domain.
// Escaped dots (\.) in the local-part become literal dots in the email address.
// This is a best-effort decoder; exotic escape sequences beyond \. are uncommon.
func decodeRNAME(rname string) (string, error) {
	rname = strings.TrimSuffix(rname, ".")

	// Find the first unescaped dot. A dot is escaped only if preceded by an
	// odd number of backslashes (e.g. \. is escaped, \\. is not).
	boundary := -1
	for i := 0; i < len(rname); i++ {
		if rname[i] == '.' {
			bs := 0
			for j := i - 1; j >= 0 && rname[j] == '\\'; j-- {
				bs++
			}
			if bs%2 == 0 {
				boundary = i
				break
			}
		}
	}

	if boundary <= 0 || boundary >= len(rname)-1 {
		return "", fmt.Errorf("invalid RNAME: must contain both local-part and domain")
	}

	localPart := strings.ReplaceAll(rname[:boundary], "\\.", ".")
	localPart = strings.ReplaceAll(localPart, "\\\\", "\\")
	domain := rname[boundary+1:]

	return localPart + "@" + domain, nil
}

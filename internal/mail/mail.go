package mail

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

type Records struct {
	MX    []MXRecord
	SPF   string
	DMARC string
	DKIM  []DKIMRecord
	BIMI  *BIMIRecord `json:",omitempty"`
}

type MXRecord struct {
	Host     string
	Priority uint16
}

type DKIMRecord struct {
	Selector string
	Value    string
}

type BIMIRecord struct {
	Raw     string   `json:",omitempty"`
	LogoURL string   `json:",omitempty"`
	VMCURL  string   `json:",omitempty"`
	VMC     *VMCInfo `json:",omitempty"`
}

type VMCInfo struct {
	Subject    string    `json:",omitempty"`
	Issuer     string    `json:",omitempty"`
	NotBefore  time.Time `json:",omitempty"`
	NotAfter   time.Time `json:",omitempty"`
	IsExpired  bool      `json:",omitempty"`
	DaysLeft   int       `json:",omitempty"`
	ChainValid bool      `json:",omitempty"`
	HasBIMIEKU bool      `json:",omitempty"`
	Error      string    `json:",omitempty"`
}

const timeout = 5 * time.Second

// Common DKIM selectors used by popular email providers
var dkimSelectors = []string{
	"default",
	"google",
	"selector1", // Microsoft
	"selector2", // Microsoft
	"k1",        // Mailchimp
	"mandrill",
	"s1",
	"s2",
	"mail",
	"dkim",
	"sm1",  // Salesforce
	"sm2",  // Salesforce
	"sig1", // Hubspot
}

// Lookup queries MX, SPF, DKIM, and DMARC records for the given domain.
func Lookup(domain string) (*Records, error) {
	resolver := findResolver()
	records := &Records{}

	// MX
	if rr, err := query(domain+".", mdns.TypeMX, resolver); err == nil {
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

	// SPF — look for "v=spf1" in TXT records
	if rr, err := query(domain+".", mdns.TypeTXT, resolver); err == nil {
		for _, r := range rr {
			if txt, ok := r.(*mdns.TXT); ok {
				val := strings.Join(txt.Txt, "")
				if strings.HasPrefix(strings.ToLower(val), "v=spf1") {
					records.SPF = val
					break
				}
			}
		}
	}

	// DMARC — TXT record at _dmarc.<domain>
	if rr, err := query("_dmarc."+domain+".", mdns.TypeTXT, resolver); err == nil {
		for _, r := range rr {
			if txt, ok := r.(*mdns.TXT); ok {
				val := strings.Join(txt.Txt, "")
				if strings.HasPrefix(strings.ToLower(val), "v=dmarc1") {
					records.DMARC = val
					break
				}
			}
		}
	}

	// BIMI — TXT at default._bimi.<domain>
	if rr, err := query("default._bimi."+domain+".", mdns.TypeTXT, resolver); err == nil {
		for _, r := range rr {
			if txt, ok := r.(*mdns.TXT); ok {
				val := strings.Join(txt.Txt, "")
				if strings.HasPrefix(strings.ToLower(val), "v=bimi1") {
					records.BIMI = parseBIMI(val)
					break
				}
			}
		}
	}
	if records.BIMI != nil && records.BIMI.VMCURL != "" {
		records.BIMI.VMC = fetchVMC(records.BIMI.VMCURL)
	}

	// DKIM — probe common selectors
	for _, sel := range dkimSelectors {
		qname := sel + "._domainkey." + domain + "."
		if rr, err := query(qname, mdns.TypeTXT, resolver); err == nil {
			for _, r := range rr {
				if txt, ok := r.(*mdns.TXT); ok {
					val := strings.Join(txt.Txt, "")
					if strings.Contains(strings.ToLower(val), "v=dkim1") {
						records.DKIM = append(records.DKIM, DKIMRecord{
							Selector: sel,
							Value:    val,
						})
					}
				}
			}
		}
	}

	return records, nil
}

func query(name string, qtype uint16, resolver string) ([]mdns.RR, error) {
	msg := new(mdns.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = true

	client := &mdns.Client{Timeout: timeout}
	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != mdns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed: %s", mdns.RcodeToString[resp.Rcode])
	}
	return resp.Answer, nil
}

func findResolver() string {
	config, err := mdns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(config.Servers) > 0 {
		return net.JoinHostPort(config.Servers[0], config.Port)
	}
	return "1.1.1.1:53"
}

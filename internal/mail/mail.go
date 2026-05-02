package mail

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/retlehs/quien/internal/dnsutil"
)

// DKIMSelectorsEnvVar holds a comma-separated list of DKIM selectors that are
// probed in addition to the built-in common-selector list.
const DKIMSelectorsEnvVar = "QUIEN_DKIM_SELECTORS"

type Records struct {
	MX          []MXRecord
	SPF         string
	SPFAnalysis *SPFAnalysis `json:",omitempty"`
	DMARC       string
	DKIM        []DKIMRecord
	BIMI        *BIMIRecord `json:",omitempty"`
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

// LookupOptions tunes Lookup behavior.
type LookupOptions struct {
	// DKIMSelectors are user-supplied selectors probed in addition to the
	// built-in common-selector list. User selectors are probed first; the
	// merged list is deduped (case-insensitive, whitespace-trimmed).
	// When empty, QUIEN_DKIM_SELECTORS is consulted as a fallback.
	DKIMSelectors []string
}

// Lookup queries MX, SPF, DKIM, and DMARC records for the given domain.
// User selectors from QUIEN_DKIM_SELECTORS, if set, are probed alongside the
// built-in common-selector list.
func Lookup(domain string) (*Records, error) {
	return LookupWithOptions(domain, LookupOptions{})
}

// LookupWithOptions is Lookup with caller-controlled options. When
// opts.DKIMSelectors is empty, QUIEN_DKIM_SELECTORS is used as a fallback.
func LookupWithOptions(domain string, opts LookupOptions) (*Records, error) {
	resolver := findResolver()
	records := &Records{}

	userSelectors := opts.DKIMSelectors
	if len(userSelectors) == 0 {
		userSelectors = selectorsFromEnv()
	}

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

	// SPF — analyze and walk include/redirect chain. AnalyzeSPF collects all
	// v=spf1 records at the root so multi-record (PermError) is detected.
	analysis := AnalyzeSPF(domain, nil)
	if len(analysis.Records) > 0 {
		records.SPF = analysis.Records[0]
		records.SPFAnalysis = analysis
	} else if len(analysis.Errors) > 0 {
		records.SPFAnalysis = analysis
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

	// DKIM — probe merged selector list in parallel
	records.DKIM = lookupDKIM(domain, mergeDKIMSelectors(userSelectors, dkimSelectors), resolver)

	return records, nil
}

// selectorsFromEnv parses QUIEN_DKIM_SELECTORS into a slice. The env var is a
// comma-separated list; whitespace is trimmed and empty entries are dropped.
func selectorsFromEnv() []string {
	raw := strings.TrimSpace(os.Getenv(DKIMSelectorsEnvVar))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// mergeDKIMSelectors returns user selectors first, then defaults, deduped
// (case-insensitive after trimming) and dropping any empty entries.
func mergeDKIMSelectors(user, defaults []string) []string {
	merged := make([]string, 0, len(user)+len(defaults))
	seen := map[string]struct{}{}
	for _, src := range [][]string{user, defaults} {
		for _, s := range src {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			key := strings.ToLower(s)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			merged = append(merged, s)
		}
	}
	return merged
}

// lookupDKIM probes each selector concurrently and returns matching v=DKIM1
// TXT records in selector-order.
func lookupDKIM(domain string, selectors []string, resolver string) []DKIMRecord {
	if len(selectors) == 0 {
		return nil
	}
	results := make([][]DKIMRecord, len(selectors))
	var wg sync.WaitGroup
	for i, sel := range selectors {
		wg.Add(1)
		go func(i int, sel string) {
			defer wg.Done()
			qname := sel + "._domainkey." + domain + "."
			rr, err := query(qname, mdns.TypeTXT, resolver)
			if err != nil {
				return
			}
			for _, r := range rr {
				txt, ok := r.(*mdns.TXT)
				if !ok {
					continue
				}
				val := strings.Join(txt.Txt, "")
				if strings.Contains(strings.ToLower(val), "v=dkim1") {
					results[i] = append(results[i], DKIMRecord{Selector: sel, Value: val})
				}
			}
		}(i, sel)
	}
	wg.Wait()

	var out []DKIMRecord
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

// MXResolution pairs an MX host with its resolved IP addresses (and reverse DNS).
type MXResolution struct {
	Host string
	IPs  []MXIP
	Err  string
}

type MXIP struct {
	IP  string
	PTR string
}

// ResolveMX looks up A/AAAA records and reverse DNS for each MX host concurrently.
func ResolveMX(hosts []string) []MXResolution {
	out := make([]MXResolution, len(hosts))
	resolver := resolverForMX()
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			out[i].Host = host
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			addrs, err := resolver.LookupIPAddr(ctx, host)
			if err != nil {
				out[i].Err = err.Error()
				return
			}
			ips := make([]MXIP, len(addrs))
			var inner sync.WaitGroup
			for j, a := range addrs {
				ips[j].IP = a.IP.String()
				inner.Add(1)
				go func(j int, ip string) {
					defer inner.Done()
					rctx, rcancel := context.WithTimeout(context.Background(), timeout)
					defer rcancel()
					names, err := resolver.LookupAddr(rctx, ip)
					if err == nil && len(names) > 0 {
						ips[j].PTR = strings.TrimSuffix(names[0], ".")
					}
				}(j, ips[j].IP)
			}
			inner.Wait()
			out[i].IPs = ips
		}(i, h)
	}
	wg.Wait()
	return out
}

func resolverForMX() *net.Resolver {
	return dnsutil.GoResolver(timeout)
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

func findResolver() string {
	return dnsutil.FindResolver()
}

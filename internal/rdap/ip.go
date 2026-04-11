package rdap

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/retlehs/quien/internal/bgp"
	"github.com/retlehs/quien/internal/peeringdb"
)

type IPInfo struct {
	IP              string
	Name            string
	Handle          string
	Network         string // CIDR
	Type            string
	Country         string
	StartAddr       string
	EndAddr         string
	ASN             []ASNInfo
	BGP             *bgp.RouteInfo
	BGPStatus       string
	PeeringDB       *peeringdb.Network
	PeeringDBStatus string
	Org             string
	Abuse           string
	Hostnames       []string // reverse DNS
}

type ASNInfo struct {
	Handle string
	Name   string
	ASN    int
}

type ipRDAPResponse struct {
	Handle    string       `json:"handle"`
	Name      string       `json:"name"`
	Type      string       `json:"type"`
	StartAddr string       `json:"startAddress"`
	EndAddr   string       `json:"endAddress"`
	Country   string       `json:"country"`
	CIDRs     []rdapCIDR   `json:"cidr0_cidrs"`
	Entities  []rdapEntity `json:"entities"`
	AutNums   []rdapAutNum `json:"autnums"`
}

type rdapCIDR struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

type rdapAutNum struct {
	Handle      string `json:"handle"`
	Name        string `json:"name"`
	StartAutNum int    `json:"startAutnum"`
}

var (
	ipv4Bootstrap struct {
		sync.RWMutex
		services map[string]string // CIDR -> RDAP URL
		entries  []ipBootstrapEntry
		loaded   bool
	}
	ipv6Bootstrap struct {
		sync.RWMutex
		services map[string]string
		entries  []ipBootstrapEntry
		loaded   bool
	}
)

type ipBootstrapEntry struct {
	prefix  string
	baseURL string
}

const (
	ipv4BootstrapURL = "https://data.iana.org/rdap/ipv4.json"
	ipv6BootstrapURL = "https://data.iana.org/rdap/ipv6.json"
)

// QueryIP performs an RDAP lookup for an IP address.
func QueryIP(ip string) (*IPInfo, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	isV6 := parsed.To4() == nil
	baseURL, err := findIPServer(ip, isV6)
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	url := baseURL + "ip/" + ip
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("RDAP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("RDAP returned status %d", resp.StatusCode)
	}

	var rdap ipRDAPResponse
	if err := json.NewDecoder(resp.Body).Decode(&rdap); err != nil {
		return nil, fmt.Errorf("parsing RDAP response: %w", err)
	}

	info := convertIPRDAP(&rdap, ip)

	asn := firstASN(info.ASN)
	var (
		hostnames []string
		bgpInfo   *bgp.RouteInfo
		peerNet   *peeringdb.Network
		bgpStatus string
		pdbStatus string
		fallback  *ASNInfo
		wg        sync.WaitGroup
	)

	// Run optional enrichment lookups concurrently to avoid serial latency.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if names, err := net.LookupAddr(ip); err == nil {
			for _, n := range names {
				hostnames = append(hostnames, strings.TrimSuffix(n, "."))
			}
		}
	}()

	if asn > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// PeeringDB is best-effort enrichment; keep base IP lookup resilient.
			if p, err := peeringdb.LookupASN(asn); err == nil {
				peerNet = p
				pdbStatus = "Enriched via RDAP ASN"
			} else {
				pdbStatus = "Lookup failed"
			}
		}()
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// BGP fallback is best-effort when RDAP lacks ASN/autnum data.
			b, err := bgp.LookupIP(ip)
			if err != nil {
				bgpStatus = "Lookup failed"
				pdbStatus = "No ASN available"
				return
			}
			bgpInfo = b
			asn = b.OriginASN
			fallback = &ASNInfo{ASN: asn}

			if p, err := peeringdb.LookupASN(asn); err == nil {
				peerNet = p
				pdbStatus = "Enriched via BGP ASN"
			} else {
				pdbStatus = "Lookup failed"
			}
		}()
	}
	wg.Wait()

	info.Hostnames = hostnames
	if fallback != nil {
		info.ASN = append(info.ASN, *fallback)
	}
	info.BGP = bgpInfo
	info.BGPStatus = bgpStatus
	info.PeeringDB = peerNet
	info.PeeringDBStatus = pdbStatus

	return info, nil
}

func convertIPRDAP(r *ipRDAPResponse, ip string) *IPInfo {
	info := &IPInfo{
		IP:        ip,
		Name:      r.Name,
		Handle:    r.Handle,
		Type:      r.Type,
		Country:   r.Country,
		StartAddr: r.StartAddr,
		EndAddr:   r.EndAddr,
	}

	// Build CIDR from response
	for _, cidr := range r.CIDRs {
		if cidr.V4Prefix != "" {
			info.Network = fmt.Sprintf("%s/%d", cidr.V4Prefix, cidr.Length)
			break
		}
		if cidr.V6Prefix != "" {
			info.Network = fmt.Sprintf("%s/%d", cidr.V6Prefix, cidr.Length)
			break
		}
	}
	if info.Network == "" && r.StartAddr != "" && r.EndAddr != "" {
		info.Network = r.StartAddr + " - " + r.EndAddr
	}

	// Extract org and abuse from entities
	for _, ent := range r.Entities {
		for _, role := range ent.Roles {
			if role == "registrant" {
				info.Org = extractVCardFN(ent.VCardArray)
			}
			if role == "abuse" {
				info.Abuse = extractVCardEmail(ent.VCardArray)
			}
		}
		// Check nested entities for abuse contact
		for _, nested := range ent.Entities {
			for _, role := range nested.Roles {
				if role == "abuse" {
					if email := extractVCardEmail(nested.VCardArray); email != "" {
						info.Abuse = email
					}
				}
			}
		}
		// Use any org we can find
		if info.Org == "" {
			for _, role := range ent.Roles {
				if role == "registrant" || role == "administrative" {
					if fn := extractVCardFN(ent.VCardArray); fn != "" {
						info.Org = fn
					}
				}
			}
		}
	}

	for _, autNum := range r.AutNums {
		if autNum.StartAutNum <= 0 {
			continue
		}
		info.ASN = append(info.ASN, ASNInfo{
			Handle: autNum.Handle,
			Name:   autNum.Name,
			ASN:    autNum.StartAutNum,
		})
	}

	return info
}

func firstASN(asns []ASNInfo) int {
	for _, a := range asns {
		if a.ASN > 0 {
			return a.ASN
		}
	}
	return 0
}

func extractVCardEmail(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	entries, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, entry := range entries {
		arr, ok := entry.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		prop, _ := arr[0].(string)
		if prop == "email" {
			val, _ := arr[3].(string)
			return val
		}
	}
	return ""
}

func findIPServer(ip string, isV6 bool) (string, error) {
	if isV6 {
		return findIPServerFromBootstrap(ip, ipv6BootstrapURL, &ipv6Bootstrap)
	}
	return findIPServerFromBootstrap(ip, ipv4BootstrapURL, &ipv4Bootstrap)
}

func findIPServerFromBootstrap(ip string, bootstrapURL string, cache *struct {
	sync.RWMutex
	services map[string]string
	entries  []ipBootstrapEntry
	loaded   bool
}) (string, error) {
	cache.RLock()
	if cache.loaded {
		url := matchIP(ip, cache.entries)
		cache.RUnlock()
		if url != "" {
			return url, nil
		}
		return "", fmt.Errorf("no RDAP server found for %s", ip)
	}
	cache.RUnlock()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(bootstrapURL)
	if err != nil {
		return "", fmt.Errorf("fetching IP bootstrap: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var data bootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("parsing IP bootstrap: %w", err)
	}

	var entries []ipBootstrapEntry
	for _, entry := range data.Services {
		if len(entry) != 2 {
			continue
		}
		prefixes := entry[0]
		urls := entry[1]
		if len(urls) == 0 {
			continue
		}
		for _, prefix := range prefixes {
			entries = append(entries, ipBootstrapEntry{
				prefix:  prefix,
				baseURL: urls[0],
			})
		}
	}

	cache.Lock()
	cache.entries = entries
	cache.loaded = true
	cache.Unlock()

	url := matchIP(ip, entries)
	if url != "" {
		return url, nil
	}
	return "", fmt.Errorf("no RDAP server found for %s", ip)
}

func matchIP(ipStr string, entries []ipBootstrapEntry) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	bestLen := -1
	bestURL := ""

	for _, e := range entries {
		_, cidr, err := net.ParseCIDR(e.prefix)
		if err != nil {
			// Try as bare prefix (some entries are like "41" meaning 41.0.0.0/8)
			continue
		}
		if cidr.Contains(ip) {
			ones, _ := cidr.Mask.Size()
			if ones > bestLen {
				bestLen = ones
				bestURL = e.baseURL
			}
		}
	}

	return bestURL
}

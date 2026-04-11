package bgp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultBaseURL = "https://stat.ripe.net/data"
	userAgent      = "quien/0 (+https://github.com/retlehs/quien)"
)

var (
	baseURL = defaultBaseURL
	client  = &http.Client{Timeout: 10 * time.Second}
)

type RouteInfo struct {
	Resource  string
	Prefix    string
	OriginASN int
	SourceID  string
}

type state struct {
	TargetPrefix string `json:"target_prefix"`
	Prefix       string `json:"prefix"`
	Path         []int  `json:"path"`
	Origin       int    `json:"origin"`
	SourceID     string `json:"source_id"`
}

type response struct {
	Data struct {
		Resource string  `json:"resource"`
		BGPState []state `json:"bgp_state"`
	} `json:"data"`
}

// LookupIP resolves BGP route state for an IP and returns origin ASN/prefix.
func LookupIP(ip string) (*RouteInfo, error) {
	url := fmt.Sprintf("%s/bgp-state/data.json?resource=%s", baseURL, ip)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building bgp request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bgp request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bgp endpoint returned status %d", resp.StatusCode)
	}

	var out response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("parsing bgp response: %w", err)
	}

	for _, s := range out.Data.BGPState {
		asn := s.Origin
		if asn == 0 && len(s.Path) > 0 {
			asn = s.Path[len(s.Path)-1]
		}
		if asn <= 0 {
			continue
		}
		prefix := s.TargetPrefix
		if prefix == "" {
			prefix = s.Prefix
		}
		return &RouteInfo{
			Resource:  out.Data.Resource,
			Prefix:    prefix,
			OriginASN: asn,
			SourceID:  s.SourceID,
		}, nil
	}

	return nil, fmt.Errorf("no bgp origin ASN found for %s", ip)
}

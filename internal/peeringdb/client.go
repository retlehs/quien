package peeringdb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const defaultBaseURL = "https://www.peeringdb.com/api"
const userAgent = "quien/0 (+https://github.com/retlehs/quien)"

var (
	baseURL = defaultBaseURL
	client  = &http.Client{Timeout: 10 * time.Second}
)

type Network struct {
	ASN           int
	Name          string
	NameLong      string
	Website       string
	PolicyGeneral string
	PolicyRatio   string
	PolicyLocs    string
	Traffic       string
	IXCount       int
	FacilityCount int
}

type netResponse struct {
	Data []struct {
		ASN           int    `json:"asn"`
		Name          string `json:"name"`
		NameLong      string `json:"name_long"`
		Website       string `json:"website"`
		PolicyGeneral string `json:"policy_general"`
		PolicyRatio   any    `json:"policy_ratio"`
		PolicyLocs    string `json:"policy_locations"`
		Traffic       string `json:"info_traffic"`
		IXCount       int    `json:"ix_count"`
		FacilityCount int    `json:"fac_count"`
	} `json:"data"`
}

func policyRatioValue(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case bool:
		// PeeringDB may return false for unset values. Hide that from users.
		return ""
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", x))
	}
}

// LookupASN fetches network details for a specific ASN from PeeringDB.
func LookupASN(asn int) (*Network, error) {
	if asn <= 0 {
		return nil, fmt.Errorf("invalid ASN: %d", asn)
	}

	url := fmt.Sprintf("%s/net?asn=%d", baseURL, asn)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building peeringdb request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("peeringdb request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("peeringdb returned status %d", resp.StatusCode)
	}

	var out netResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("parsing peeringdb response: %w", err)
	}
	if len(out.Data) == 0 {
		return nil, fmt.Errorf("no peeringdb record found for AS%d", asn)
	}

	n := out.Data[0]
	return &Network{
		ASN:           n.ASN,
		Name:          n.Name,
		NameLong:      n.NameLong,
		Website:       n.Website,
		PolicyGeneral: n.PolicyGeneral,
		PolicyRatio:   policyRatioValue(n.PolicyRatio),
		PolicyLocs:    n.PolicyLocs,
		Traffic:       n.Traffic,
		IXCount:       n.IXCount,
		FacilityCount: n.FacilityCount,
	}, nil
}

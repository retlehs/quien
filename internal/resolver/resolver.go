package resolver

import (
	"fmt"
	"sync"

	"github.com/retlehs/quien/internal/model"
	"github.com/retlehs/quien/internal/rdap"
	"github.com/retlehs/quien/internal/retry"
	"github.com/retlehs/quien/internal/whois"
)

// LookupIP performs an RDAP lookup for an IP address with retry.
func LookupIP(ip string) (*rdap.IPInfo, error) {
	return retry.Do(func() (*rdap.IPInfo, error) {
		return rdap.QueryIP(ip)
	})
}

// Lookup runs RDAP and WHOIS in parallel. RDAP is preferred for structured
// data; WHOIS is used to fill in fields the registry RDAP omits (e.g. PIR/.org
// returns no registrant entities, so we chase the registrar's WHOIS for
// contacts) and to populate the raw view. WHOIS alone is the fallback when
// RDAP isn't available for the TLD.
func Lookup(domain string) (*model.DomainInfo, error) {
	target, err := RegistrableDomain(domain)
	if err != nil {
		return nil, err
	}
	domain = target

	var (
		wg       sync.WaitGroup
		rdapInfo *model.DomainInfo
		whoisRaw string
		whoisErr error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		// Errors are ignored — RDAP failure just means we'll lean on WHOIS.
		rdapInfo, _ = rdap.Query(domain)
	}()
	go func() {
		defer wg.Done()
		whoisRaw, whoisErr = retry.Do(func() (string, error) {
			return whois.QueryWithReferral(domain)
		})
	}()
	wg.Wait()

	// RDAP succeeded — use it as the base, merge in any WHOIS-only fields.
	if rdapInfo != nil {
		if whoisErr == nil {
			rdapInfo.RawResponse = whoisRaw
			whoisInfo := whois.Parse(whois.Normalize(domain, whoisRaw))
			mergeFromWhois(rdapInfo, &whoisInfo)
		}
		return rdapInfo, nil
	}

	// RDAP unavailable — fall back to WHOIS alone.
	if whoisErr != nil {
		return nil, whoisErr
	}

	// Apply TLD-specific normalization (e.g. JPRS bracketed labels) before
	// emptiness check and parsing. The original response is preserved for
	// the raw view.
	normalized := whois.Normalize(domain, whoisRaw)
	if whois.LooksEmpty(normalized) {
		return nil, fmt.Errorf("domain %s not found", domain)
	}

	info := whois.Parse(normalized)
	if info.DomainName == "" {
		info.DomainName = domain
	}
	info.RawResponse = whoisRaw
	return &info, nil
}

// mergeFromWhois fills empty fields on the RDAP-derived info from the
// WHOIS-parsed equivalent. RDAP wins where both have data.
func mergeFromWhois(info *model.DomainInfo, w *model.DomainInfo) {
	if info.Registrar == "" {
		info.Registrar = w.Registrar
	}
	if len(info.Status) == 0 {
		info.Status = w.Status
	}
	if len(info.Nameservers) == 0 {
		info.Nameservers = w.Nameservers
	}
	if info.CreatedDate.IsZero() {
		info.CreatedDate = w.CreatedDate
	}
	if info.UpdatedDate.IsZero() {
		info.UpdatedDate = w.UpdatedDate
	}
	if info.ExpiryDate.IsZero() {
		info.ExpiryDate = w.ExpiryDate
	}
	if len(info.Contacts) == 0 {
		info.Contacts = w.Contacts
	}
}

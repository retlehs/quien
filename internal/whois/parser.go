package whois

import (
	"strings"
	"time"

	"github.com/retlehs/quien/internal/model"
)

// Common date formats found in WHOIS responses
var dateFormats = []string{
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05-0700",
	"2006-01-02T15:04:05-07:00",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"January 02 2006",
	"20060102",
	"2006/01/02",
	"02/01/2006",
	"2006-01-02 15:04:05 MST",
	"2006-01-02 15:04:05-07",
	"Mon Jan 2 15:04:05 MST 2006",
	"Mon Jan 2 2006",
}

// Parse extracts structured domain info from a raw WHOIS response.
func Parse(raw string) model.DomainInfo {
	info := model.DomainInfo{
		RawResponse: raw,
	}

	kv := extractKeyValues(raw)

	info.DomainName = firstValue(kv, "domain name", "domain")
	info.Registrar = firstValue(kv, "registrar", "registrar name", "name")
	info.Status = allValues(kv, "domain status", "status")
	info.Nameservers = allValues(kv, "name server", "nameserver", "nameservers", "nserver")
	info.CreatedDate = parseDate(firstValue(kv, "creation date", "created", "created date", "registration date", "registered on", "registered", "registration time"))
	info.UpdatedDate = parseDate(firstValue(kv, "updated date", "last update", "last updated", "last modified", "changed"))
	info.ExpiryDate = parseDate(firstValue(kv, "registry expiry date", "registrar registration expiration date", "expire date", "expiry date", "expiration date", "expires on", "expires", "paid-till"))

	dnssec := strings.ToLower(firstValue(kv, "dnssec"))
	info.DNSSEC = dnssec == "signeddelegation" || dnssec == "yes" || dnssec == "signed"

	// Extract contacts
	registrant := extractContact(kv, "registrant", "registrant")
	if registrant.Name != "" || registrant.Organization != "" || registrant.Email != "" {
		info.Contacts = append(info.Contacts, registrant)
	}
	admin := extractContact(kv, "admin", "admin")
	if admin.Name != "" || admin.Organization != "" || admin.Email != "" {
		info.Contacts = append(info.Contacts, admin)
	}
	tech := extractContact(kv, "tech", "tech")
	if tech.Name != "" || tech.Organization != "" || tech.Email != "" {
		info.Contacts = append(info.Contacts, tech)
	}

	// Clean up status values (remove URLs appended after space, e.g. "clientDeleteProhibited https://...")
	for i, s := range info.Status {
		if idx := strings.Index(s, " "); idx != -1 {
			rest := strings.TrimSpace(s[idx+1:])
			if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
				info.Status[i] = s[:idx]
			}
		}
	}

	return info
}

func extractKeyValues(raw string) map[string][]string {
	kv := make(map[string][]string)
	var lastKey string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "%") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ">") {
			lastKey = ""
			continue
		}
		idx := strings.Index(trimmed, ":")
		if idx == -1 {
			// Tab-indented continuation line (e.g. .be nameservers)
			if lastKey != "" && (strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "  ")) {
				if trimmed != "" {
					kv[lastKey] = append(kv[lastKey], trimmed)
				}
			}
			continue
		}
		key := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
		value := strings.TrimSpace(trimmed[idx+1:])
		if value != "" {
			kv[key] = append(kv[key], value)
			lastKey = ""
		} else {
			// Section header with no value — subsequent indented lines belong to it
			lastKey = key
		}
	}
	return kv
}

func firstValue(kv map[string][]string, keys ...string) string {
	for _, key := range keys {
		if vals, ok := kv[key]; ok && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func allValues(kv map[string][]string, keys ...string) []string {
	var result []string
	seen := make(map[string]bool)
	for _, key := range keys {
		for _, v := range kv[key] {
			lower := strings.ToLower(v)
			if !seen[lower] {
				seen[lower] = true
				result = append(result, v)
			}
		}
	}
	return result
}

func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, format := range dateFormats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func extractContact(kv map[string][]string, role, prefix string) model.Contact {
	return model.Contact{
		Role:         role,
		Name:         firstValue(kv, prefix+" name", prefix+" contact name"),
		Organization: firstValue(kv, prefix+" organization", prefix+" org"),
		Email:        firstValue(kv, prefix+" email", prefix+" contact email"),
		Phone:        firstValue(kv, prefix+" phone", prefix+" contact phone"),
		Address:      firstValue(kv, prefix+" street", prefix+" address"),
	}
}

package whois

import (
	"testing"
	"time"
)

func TestParse_StandardResponse(t *testing.T) {
	raw := `Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://www.iana.org
Updated Date: 2024-08-14T07:01:38Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2025-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation`

	info := Parse(raw)

	if info.DomainName != "EXAMPLE.COM" {
		t.Errorf("DomainName = %q, want %q", info.DomainName, "EXAMPLE.COM")
	}
	if info.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Errorf("Registrar = %q", info.Registrar)
	}
	if len(info.Status) != 2 {
		t.Errorf("Status count = %d, want 2", len(info.Status))
	}
	if info.Status[0] != "clientDeleteProhibited" {
		t.Errorf("Status[0] = %q, want clientDeleteProhibited", info.Status[0])
	}
	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count = %d, want 2", len(info.Nameservers))
	}
	if !info.DNSSEC {
		t.Error("DNSSEC should be true for signedDelegation")
	}
	if info.CreatedDate.Year() != 1995 {
		t.Errorf("CreatedDate year = %d, want 1995", info.CreatedDate.Year())
	}
	if info.ExpiryDate.Year() != 2025 {
		t.Errorf("ExpiryDate year = %d, want 2025", info.ExpiryDate.Year())
	}
	if info.RawResponse != raw {
		t.Error("RawResponse should contain the original response")
	}
}

func TestParse_AlternativeDateFormats(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantYear int
	}{
		{
			name:     "ISO with timezone offset",
			raw:      "Creation Date: 2020-05-10T12:00:00+0000",
			wantYear: 2020,
		},
		{
			name:     "ISO with Z",
			raw:      "Creation Date: 2019-03-15T08:30:00Z",
			wantYear: 2019,
		},
		{
			name:     "date only",
			raw:      "Creation Date: 2018-07-22",
			wantYear: 2018,
		},
		{
			name:     "datetime with space",
			raw:      "Creation Date: 2017-01-05 14:30:00",
			wantYear: 2017,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := Parse(tt.raw)
			if info.CreatedDate.IsZero() {
				t.Fatal("CreatedDate is zero")
			}
			if info.CreatedDate.Year() != tt.wantYear {
				t.Errorf("year = %d, want %d", info.CreatedDate.Year(), tt.wantYear)
			}
		})
	}
}

func TestParse_Contacts(t *testing.T) {
	raw := `Domain Name: test.com
Registrant Name: John Doe
Registrant Organization: Example Inc
Registrant Email: john@example.com
Admin Name: Jane Admin
Admin Email: jane@example.com
Tech Name: Tech Support
Tech Phone: +1.5551234567`

	info := Parse(raw)

	if len(info.Contacts) != 3 {
		t.Fatalf("Contacts count = %d, want 3", len(info.Contacts))
	}

	reg := info.Contacts[0]
	if reg.Role != "registrant" {
		t.Errorf("Contact[0] role = %q, want registrant", reg.Role)
	}
	if reg.Name != "John Doe" {
		t.Errorf("Registrant name = %q", reg.Name)
	}
	if reg.Organization != "Example Inc" {
		t.Errorf("Registrant org = %q", reg.Organization)
	}
	if reg.Email != "john@example.com" {
		t.Errorf("Registrant email = %q", reg.Email)
	}

	admin := info.Contacts[1]
	if admin.Name != "Jane Admin" {
		t.Errorf("Admin name = %q", admin.Name)
	}

	tech := info.Contacts[2]
	if tech.Phone != "+1.5551234567" {
		t.Errorf("Tech phone = %q", tech.Phone)
	}
}

func TestParse_StatusURLStripping(t *testing.T) {
	raw := `Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited`

	info := Parse(raw)

	if len(info.Status) != 1 {
		t.Fatalf("Status count = %d, want 1", len(info.Status))
	}
	if info.Status[0] != "clientTransferProhibited" {
		t.Errorf("Status = %q, want clientTransferProhibited", info.Status[0])
	}
}

func TestParse_EmptyResponse(t *testing.T) {
	info := Parse("")

	if info.DomainName != "" {
		t.Errorf("DomainName should be empty, got %q", info.DomainName)
	}
	if !info.CreatedDate.IsZero() {
		t.Error("CreatedDate should be zero")
	}
}

func TestParse_DNSSECVariants(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{"DNSSEC: signedDelegation", true},
		{"DNSSEC: yes", true},
		{"DNSSEC: signed", true},
		{"DNSSEC: unsigned", false},
		{"DNSSEC: no", false},
		{"", false},
	}

	for _, tt := range tests {
		info := Parse(tt.raw)
		if info.DNSSEC != tt.want {
			t.Errorf("Parse(%q).DNSSEC = %v, want %v", tt.raw, info.DNSSEC, tt.want)
		}
	}
}

func TestParse_DuplicateNameservers(t *testing.T) {
	raw := `Name Server: ns1.example.com
Name Server: ns2.example.com
Name Server: ns1.example.com`

	info := Parse(raw)

	if len(info.Nameservers) != 2 {
		t.Errorf("Nameservers count = %d, want 2 (deduped)", len(info.Nameservers))
	}
}

func TestParse_ITStyleFields(t *testing.T) {
	raw := `Domain:             example.it
Status:             ok
Created:            1998-10-29 00:00:00
Last Update:        2026-03-05 00:53:35
Expire Date:        2027-02-17`

	info := Parse(raw)

	if info.DomainName != "example.it" {
		t.Errorf("DomainName = %q, want example.it", info.DomainName)
	}
	if info.CreatedDate.Year() != 1998 {
		t.Errorf("CreatedDate year = %d, want 1998", info.CreatedDate.Year())
	}
	if info.UpdatedDate.Year() != 2026 {
		t.Errorf("UpdatedDate year = %d, want 2026", info.UpdatedDate.Year())
	}
	if info.ExpiryDate.Year() != 2027 {
		t.Errorf("ExpiryDate year = %d, want 2027", info.ExpiryDate.Year())
	}
}

func TestParseDate(t *testing.T) {
	tests := []struct {
		input string
		want  time.Time
	}{
		{"", time.Time{}},
		{"not-a-date", time.Time{}},
		{"2024-01-15", time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)},
		{"2024-01-15T10:30:00Z", time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)},
	}

	for _, tt := range tests {
		got := parseDate(tt.input)
		if !got.Equal(tt.want) {
			t.Errorf("parseDate(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

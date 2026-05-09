package resolver

import (
	"reflect"
	"testing"
	"time"

	"github.com/retlehs/quien/internal/model"
)

func TestMergeFromWhois_FillsEmptyFields(t *testing.T) {
	// RDAP returned only the basics — no contacts, no registrar.
	info := &model.DomainInfo{
		DomainName: "example.org",
		Status:     []string{"active"},
	}
	whoisCreated := time.Date(2003, 3, 28, 0, 0, 0, 0, time.UTC)
	whoisExpiry := time.Date(2035, 3, 28, 0, 0, 0, 0, time.UTC)
	w := &model.DomainInfo{
		Registrar:   "MarkMonitor Inc.",
		Status:      []string{"this should be ignored"},
		Nameservers: []string{"ns1.example.org", "ns2.example.org"},
		CreatedDate: whoisCreated,
		ExpiryDate:  whoisExpiry,
		Contacts: []model.Contact{
			{Role: "registrant", Organization: "Example Org"},
		},
	}

	mergeFromWhois(info, w)

	if info.Registrar != "MarkMonitor Inc." {
		t.Errorf("Registrar = %q, want MarkMonitor Inc.", info.Registrar)
	}
	if !reflect.DeepEqual(info.Status, []string{"active"}) {
		t.Errorf("Status = %v, want [active] (RDAP value preserved)", info.Status)
	}
	if !reflect.DeepEqual(info.Nameservers, []string{"ns1.example.org", "ns2.example.org"}) {
		t.Errorf("Nameservers = %v", info.Nameservers)
	}
	if !info.CreatedDate.Equal(whoisCreated) {
		t.Errorf("CreatedDate = %v, want %v", info.CreatedDate, whoisCreated)
	}
	if !info.ExpiryDate.Equal(whoisExpiry) {
		t.Errorf("ExpiryDate = %v, want %v", info.ExpiryDate, whoisExpiry)
	}
	if len(info.Contacts) != 1 || info.Contacts[0].Organization != "Example Org" {
		t.Errorf("Contacts = %v", info.Contacts)
	}
}

func TestMergeFromWhois_RDAPWinsWhereBothHaveData(t *testing.T) {
	rdapCreated := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	whoisCreated := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	info := &model.DomainInfo{
		DomainName:  "example.com",
		Registrar:   "RDAP Registrar",
		Status:      []string{"clientHold"},
		Nameservers: []string{"a.iana-servers.net"},
		CreatedDate: rdapCreated,
		Contacts: []model.Contact{
			{Role: "registrant", Name: "From RDAP"},
		},
	}
	w := &model.DomainInfo{
		Registrar:   "WHOIS Registrar",
		Status:      []string{"ok"},
		Nameservers: []string{"x.example"},
		CreatedDate: whoisCreated,
		Contacts: []model.Contact{
			{Role: "registrant", Name: "From WHOIS"},
		},
	}

	mergeFromWhois(info, w)

	if info.Registrar != "RDAP Registrar" {
		t.Errorf("Registrar = %q, RDAP should win", info.Registrar)
	}
	if !reflect.DeepEqual(info.Status, []string{"clientHold"}) {
		t.Errorf("Status = %v, RDAP should win", info.Status)
	}
	if !reflect.DeepEqual(info.Nameservers, []string{"a.iana-servers.net"}) {
		t.Errorf("Nameservers = %v, RDAP should win", info.Nameservers)
	}
	if !info.CreatedDate.Equal(rdapCreated) {
		t.Errorf("CreatedDate = %v, RDAP should win", info.CreatedDate)
	}
	if info.Contacts[0].Name != "From RDAP" {
		t.Errorf("Contacts[0].Name = %q, RDAP should win", info.Contacts[0].Name)
	}
}

func TestMergeFromWhois_PropagatesExtensions(t *testing.T) {
	info := &model.DomainInfo{DomainName: "auda.org.au"}
	w := &model.DomainInfo{
		Extensions:       map[string]string{"Registrant": "Example Pty Ltd", "Type": "Company"},
		ExtensionSection: "Eligibility",
	}

	mergeFromWhois(info, w)

	if len(info.Extensions) != 2 {
		t.Errorf("Extensions len = %d, want 2", len(info.Extensions))
	}
	if info.Extensions["Registrant"] != "Example Pty Ltd" {
		t.Errorf("Extensions[Registrant] = %q, want Example Pty Ltd", info.Extensions["Registrant"])
	}
	if info.ExtensionSection != "Eligibility" {
		t.Errorf("ExtensionSection = %q, want Eligibility", info.ExtensionSection)
	}
}

func TestMergeFromWhois_EmptyWhoisIsNoOp(t *testing.T) {
	info := &model.DomainInfo{
		DomainName: "example.com",
		Registrar:  "Some Registrar",
		Status:     []string{"ok"},
	}
	before := *info

	mergeFromWhois(info, &model.DomainInfo{})

	if !reflect.DeepEqual(*info, before) {
		t.Errorf("empty WHOIS modified info: got %+v, want %+v", *info, before)
	}
}

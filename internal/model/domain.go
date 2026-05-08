package model

import "time"

type DomainInfo struct {
	DomainName       string            `json:"domain_name"`
	Registrar        string            `json:"registrar,omitempty"`
	Status           []string          `json:"status,omitempty"`
	CreatedDate      time.Time         `json:"created_date,omitempty"`
	UpdatedDate      time.Time         `json:"updated_date,omitempty"`
	ExpiryDate       time.Time         `json:"expiry_date,omitempty"`
	Nameservers      []string          `json:"nameservers,omitempty"`
	DNSSEC           bool              `json:"dnssec"`
	Contacts         []Contact         `json:"contacts,omitempty"`
	Extensions       map[string]string `json:"extensions,omitempty"`
	ExtensionSection string            `json:"extension_section,omitempty"`
	RawResponse      string            `json:"-"`
}

type Contact struct {
	Role         string `json:"role"`
	Name         string `json:"name,omitempty"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email,omitempty"`
	Phone        string `json:"phone,omitempty"`
	Address      string `json:"address,omitempty"`
}

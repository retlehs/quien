package whois

import "testing"

func TestLooksEmpty_ITWhoisResponse(t *testing.T) {
	resp := `Domain:             example.it
Status:             ok
Created:            1998-10-29 00:00:00
Last Update:        2026-03-05 00:53:35
Expire Date:        2027-02-17`

	if LooksEmpty(resp) {
		t.Fatal("LooksEmpty returned true for a valid .it WHOIS response")
	}
}

func TestLooksEmpty_NotFoundResponse(t *testing.T) {
	resp := `No match for domain "definitely-not-registered-example-test-12345.com"`

	if !LooksEmpty(resp) {
		t.Fatal("LooksEmpty returned false for a not-found WHOIS response")
	}
}

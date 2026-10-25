package security

import "testing"

func TestParseFieldsValidRFC9116(t *testing.T) {
	t.Parallel()

	content := `# Example security.txt
Contact: mailto:security@example.com
Contact: https://example.com/security.gpg
Encryption: https://example.com/.well-known/security.pubkey
Policy: https://example.com/security-policy
Preferred-Languages: en, es
Canonical: https://example.com/.well-known/security.txt
`

	fields := parseFields(content)

	if len(fields) != 5 {
		t.Fatalf("expected 5 fields, got %d", len(fields))
	}

	if vals, ok := fields["contact"]; !ok || len(vals) != 2 {
		t.Fatalf("expected 2 contact entries, got %v", fields["contact"])
	}

	if fields["encryption"][0] != "https://example.com/.well-known/security.pubkey" {
		t.Fatalf("unexpected encryption value: %s", fields["encryption"][0])
	}

	if fields["policy"][0] != "https://example.com/security-policy" {
		t.Fatalf("unexpected policy value: %s", fields["policy"][0])
	}
}

func TestParseFieldsSkipsNonStandardKeys(t *testing.T) {
	t.Parallel()

	content := `Contact: mailto:security@example.com
Custom-Field: some-value
X-Custom: another-value
Policy: https://example.com/policy
`

	fields := parseFields(content)

	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %v", len(fields), fields)
	}

	if _, ok := fields["custom-field"]; ok {
		t.Fatal("should not parse non-standard key 'Custom-Field'")
	}

	if _, ok := fields["x-custom"]; ok {
		t.Fatal("should not parse non-standard key 'X-Custom'")
	}
}

func TestParseFieldsSkipsCommentsAndBlanks(t *testing.T) {
	t.Parallel()

	content := `# This is a comment
Contact: mailto:test@example.com

# Another comment

Policy: https://example.com/policy
`

	fields := parseFields(content)

	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %v", len(fields), fields)
	}

	if len(fields["contact"]) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(fields["contact"]))
	}
}

func TestParseFieldsHandlesMalformedLines(t *testing.T) {
	t.Parallel()

	content := `Contact: mailto:test@example.com
no-colon-here
: empty-key
Policy: https://example.com/policy
`

	fields := parseFields(content)

	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d: %v", len(fields), fields)
	}

	if _, ok := fields[""]; ok {
		t.Fatal("should not parse empty key")
	}
}

func TestParseFieldsMultipleValuesSameKey(t *testing.T) {
	t.Parallel()

	content := `Contact: mailto:a@example.com
Contact: mailto:b@example.com
Contact: https://c@example.com
`

	fields := parseFields(content)

	if len(fields["contact"]) != 3 {
		t.Fatalf("expected 3 contact values, got %d", len(fields["contact"]))
	}
}

func TestParseFieldsCaseInsensitive(t *testing.T) {
	t.Parallel()

	content := `CONTACT: mailto:test@example.com
Contact: mailto:test2@example.com
contact: mailto:test3@example.com
`

	fields := parseFields(content)

	if len(fields["contact"]) != 3 {
		t.Fatalf("expected 3 contacts (case-insensitive), got %d", len(fields["contact"]))
	}
}

package mail

import (
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
)

// SPFAnalysis holds the parsed/expanded SPF record for a domain.
//
// The lookup count covers every term that triggers an additional DNS query
// per RFC 7208 §4.6.4: include, a, mx, ptr, exists, and the redirect modifier.
// ip4, ip6, all, and exp do not count. The hard budget is 10; over that is a
// PermError.
//
// Void lookups (NXDOMAIN or empty answers) tracked here are limited to
// include/redirect targets — we don't simulate a/mx/exists resolution, so the
// void counter only reflects what the structural walk observed.
type SPFAnalysis struct {
	Domain        string   `json:",omitempty"`
	Records       []string `json:",omitempty"` // every v=spf1 TXT at the root domain
	Root          *SPFNode `json:",omitempty"`
	LookupCount   int
	LookupLimit   int
	VoidCount     int
	VoidLimit     int
	OverLimit     bool     `json:",omitempty"` // LookupCount > LookupLimit
	OverVoidLimit bool     `json:",omitempty"` // VoidCount > VoidLimit
	Multiple      bool     `json:",omitempty"` // multiple v=spf1 records at root
	Errors        []string `json:",omitempty"`
}

// SPFNode is one term in the SPF tree.
//
// For include and redirect, Children holds the terms of the resolved child
// SPF record. For other mechanisms, Children is empty.
type SPFNode struct {
	Term         string     `json:",omitempty"` // raw token, e.g. "include:_spf.google.com"
	Qualifier    string     `json:",omitempty"` // "+", "-", "~", "?"
	Mechanism    string     `json:",omitempty"` // include, a, mx, ptr, exists, redirect, ip4, ip6, all, exp, spf1
	Target       string     `json:",omitempty"` // domain-spec, CIDR, etc.
	Record       string     `json:",omitempty"` // raw SPF record returned for include/redirect
	CountsLookup bool       `json:",omitempty"` // mechanism counts against the 10-lookup budget
	Unresolved   bool       `json:",omitempty"` // macro target — counted but not recursed into
	Void         bool       `json:",omitempty"` // include/redirect target had no SPF or NXDOMAIN
	Ignored      bool       `json:",omitempty"` // not evaluated per RFC 7208 ordering (after `all`, or redirect when `all` present)
	Error        string     `json:",omitempty"` // DNS error or structural error fetching the child record
	Children     []*SPFNode `json:",omitempty"`
}

const (
	spfLookupLimit = 10
	spfVoidLimit   = 2
	spfDepthLimit  = 10
)

// SPFLookupFunc fetches v=spf1 TXT records at domain.
// Returns void=true when the domain has no v=spf1 record (or NXDOMAIN).
type SPFLookupFunc func(domain string) (records []string, void bool, err error)

// AnalyzeSPF builds an analysis tree rooted at domain.
// All DNS access is routed through fetch. If fetch is nil, the package-default
// lookup (using the configured resolver) is used.
func AnalyzeSPF(domain string, fetch SPFLookupFunc) *SPFAnalysis {
	if fetch == nil {
		fetch = defaultSPFLookup
	}
	a := &SPFAnalysis{
		Domain:      domain,
		LookupLimit: spfLookupLimit,
		VoidLimit:   spfVoidLimit,
	}

	records, void, err := fetch(domain)
	if err != nil {
		a.Errors = append(a.Errors, err.Error())
		return a
	}
	if void || len(records) == 0 {
		return a
	}
	a.Records = records
	if len(records) > 1 {
		a.Multiple = true
	}

	a.Root = parseSPFRecord(records[0])
	visited := map[string]bool{normalizeSPFDomain(domain): true}
	expandSPF(a.Root, fetch, visited, 0, a)

	if a.LookupCount > spfLookupLimit {
		a.OverLimit = true
	}
	if a.VoidCount > spfVoidLimit {
		a.OverVoidLimit = true
	}
	return a
}

// parseSPFRecord splits a v=spf1 record into a root node whose children are
// each term. Children of include/redirect are filled in by expandSPF.
func parseSPFRecord(record string) *SPFNode {
	root := &SPFNode{
		Term:      "v=spf1",
		Mechanism: "spf1",
		Record:    record,
	}
	fields := strings.Fields(record)
	if len(fields) == 0 {
		return root
	}
	for _, f := range fields[1:] {
		root.Children = append(root.Children, parseSPFTerm(f))
	}
	return root
}

func parseSPFTerm(term string) *SPFNode {
	n := &SPFNode{Term: term}
	body := term

	// Modifiers (redirect=, exp=) carry no qualifier.
	if eq := strings.Index(body, "="); eq > 0 {
		name := strings.ToLower(body[:eq])
		switch name {
		case "redirect":
			n.Mechanism = "redirect"
			n.Target = body[eq+1:]
			n.CountsLookup = true
			if hasMacro(n.Target) {
				n.Unresolved = true
			}
			return n
		case "exp":
			n.Mechanism = "exp"
			n.Target = body[eq+1:]
			return n
		}
	}

	if body == "" {
		return n
	}
	switch body[0] {
	case '+', '-', '~', '?':
		n.Qualifier = string(body[0])
		body = body[1:]
	}

	name := body
	target := ""
	if i := strings.IndexAny(body, ":/"); i >= 0 {
		name = body[:i]
		target = strings.TrimPrefix(body[i:], ":")
	}
	n.Mechanism = strings.ToLower(name)
	n.Target = target

	switch n.Mechanism {
	case "include", "a", "mx", "ptr", "exists":
		n.CountsLookup = true
		if hasMacro(n.Target) {
			n.Unresolved = true
		}
	}
	return n
}

func hasMacro(s string) bool {
	return strings.Contains(s, "%{")
}

// normalizeSPFDomain lowercases and strips a trailing dot so cycle keys are
// consistent regardless of input shape.
func normalizeSPFDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// isSPFRecord reports whether s is a v=spf1 record per RFC 7208 §4.5:
// the version section MUST be exactly "v=spf1" (case-insensitive per §12
// ABNF), terminated by space or end of record. Rejects e.g. "v=spf10".
func isSPFRecord(s string) bool {
	const tag = "v=spf1"
	if len(s) < len(tag) || !strings.EqualFold(s[:len(tag)], tag) {
		return false
	}
	if len(s) == len(tag) {
		return true
	}
	return s[len(tag)] == ' ' || s[len(tag)] == '\t'
}

func expandSPF(node *SPFNode, fetch SPFLookupFunc, visited map[string]bool, depth int, a *SPFAnalysis) {
	if node == nil {
		return
	}

	// RFC 7208 §5.1: mechanisms after `all` MUST be ignored.
	// RFC 7208 §6.1: `redirect=` MUST be ignored if any `all` mechanism is present.
	hasAll := false
	cutoff := len(node.Children)
	for i, c := range node.Children {
		if c.Mechanism == "all" {
			hasAll = true
			cutoff = i
			break
		}
	}
	evaluated := func(i int, c *SPFNode) bool {
		// Modifiers are positional-independent.
		// redirect= is ignored if any `all` mechanism is present (§6.1).
		// exp= is consulted only when a fail result occurs (§6.2); position
		// vs. `all` doesn't apply.
		if c.Mechanism == "redirect" {
			return !hasAll
		}
		if c.Mechanism == "exp" {
			return true
		}
		// Mechanisms after `all` are ignored (§5.1).
		if hasAll && i > cutoff {
			return false
		}
		return true
	}

	for i, c := range node.Children {
		if !evaluated(i, c) {
			c.Ignored = true
			continue
		}
		if c.CountsLookup {
			a.LookupCount++
		}
	}
	if depth >= spfDepthLimit {
		a.Errors = append(a.Errors, fmt.Sprintf("max SPF depth (%d) reached", spfDepthLimit))
		return
	}

	for i, c := range node.Children {
		if c.Mechanism != "include" && c.Mechanism != "redirect" {
			continue
		}
		if c.Ignored || !evaluated(i, c) {
			continue
		}
		if c.Unresolved || c.Target == "" {
			continue
		}
		target := normalizeSPFDomain(c.Target)
		if visited[target] {
			c.Error = "cycle"
			continue
		}
		records, void, err := fetch(c.Target)
		if err != nil {
			c.Error = err.Error()
			continue
		}
		if void || len(records) == 0 {
			c.Void = true
			a.VoidCount++
			continue
		}
		if len(records) > 1 {
			c.Error = "multiple SPF records"
			continue
		}
		c.Record = records[0]
		sub := parseSPFRecord(records[0])
		c.Children = sub.Children
		visited[target] = true
		expandSPF(c, fetch, visited, depth+1, a)
		delete(visited, target) // path-scoped: sibling re-visits are fine
	}
}

// defaultSPFLookup queries TXT records at domain via the configured resolver
// and filters for v=spf1. Returns void=true on NXDOMAIN or when no v=spf1
// record is present.
func defaultSPFLookup(domain string) ([]string, bool, error) {
	resolver := findResolver()
	qname := strings.TrimSuffix(domain, ".") + "."

	msg := new(mdns.Msg)
	msg.SetQuestion(qname, mdns.TypeTXT)
	msg.RecursionDesired = true

	client := &mdns.Client{Timeout: timeout}
	resp, _, err := client.Exchange(msg, resolver)
	if err != nil {
		return nil, false, err
	}
	if resp.Truncated {
		tcpClient := &mdns.Client{Timeout: timeout, Net: "tcp"}
		resp, _, err = tcpClient.Exchange(msg, resolver)
		if err != nil {
			return nil, false, err
		}
	}
	switch resp.Rcode {
	case mdns.RcodeSuccess:
	case mdns.RcodeNameError:
		return nil, true, nil
	default:
		return nil, false, fmt.Errorf("DNS query failed: %s", mdns.RcodeToString[resp.Rcode])
	}

	var spfs []string
	for _, r := range resp.Answer {
		if txt, ok := r.(*mdns.TXT); ok {
			val := strings.Join(txt.Txt, "")
			if isSPFRecord(val) {
				spfs = append(spfs, val)
			}
		}
	}
	if len(spfs) == 0 {
		return nil, true, nil
	}
	return spfs, false, nil
}

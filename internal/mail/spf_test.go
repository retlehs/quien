package mail

import (
	"errors"
	"net"
	"strings"
	"testing"

	mdns "github.com/miekg/dns"
)

// stubLookup builds an SPFLookupFunc from a static map of domain → records.
// A domain mapped to nil returns void. Unknown domains return NXDOMAIN-style void.
type stubLookup struct {
	records map[string][]string
	errs    map[string]error
	calls   map[string]int
}

func newStub() *stubLookup {
	return &stubLookup{
		records: map[string][]string{},
		errs:    map[string]error{},
		calls:   map[string]int{},
	}
}

func (s *stubLookup) set(domain string, records ...string) *stubLookup {
	s.records[strings.ToLower(domain)] = records
	return s
}

func (s *stubLookup) void(domain string) *stubLookup {
	s.records[strings.ToLower(domain)] = nil
	return s
}

func (s *stubLookup) fail(domain string, err error) *stubLookup {
	s.errs[strings.ToLower(domain)] = err
	return s
}

func (s *stubLookup) fn() SPFLookupFunc {
	return func(domain string) ([]string, bool, error) {
		key := strings.ToLower(strings.TrimSuffix(domain, "."))
		s.calls[key]++
		if err, ok := s.errs[key]; ok {
			return nil, false, err
		}
		recs, present := s.records[key]
		if !present {
			return nil, true, nil
		}
		if len(recs) == 0 {
			return nil, true, nil
		}
		return recs, false, nil
	}
}

func TestAnalyzeSPF_CountsLookupMechanisms(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 ip4:1.2.3.4 a mx ptr exists:%{i}._spf.example.com -all")

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 4 {
		t.Fatalf("LookupCount = %d, want 4 (a + mx + ptr + exists)", a.LookupCount)
	}
	if a.OverLimit {
		t.Fatal("OverLimit set unexpectedly")
	}
	if a.Root == nil {
		t.Fatal("Root nil")
	}
	if len(a.Root.Children) != 6 {
		t.Fatalf("Root.Children = %d, want 6", len(a.Root.Children))
	}
}

func TestAnalyzeSPF_IncludeRedirectExpand(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 include:_spf.google.com redirect=fallback.example.com").
		set("_spf.google.com", "v=spf1 include:_netblocks.google.com -all").
		set("_netblocks.google.com", "v=spf1 ip4:64.233.160.0/19 -all").
		set("fallback.example.com", "v=spf1 ip4:5.6.7.8 -all")

	a := AnalyzeSPF("example.com", stub.fn())

	// include + redirect + nested include = 3 lookups.
	if a.LookupCount != 3 {
		t.Fatalf("LookupCount = %d, want 3", a.LookupCount)
	}
	if a.Root == nil || len(a.Root.Children) != 2 {
		t.Fatalf("expected 2 root children")
	}
	inc := a.Root.Children[0]
	if inc.Mechanism != "include" {
		t.Fatalf("first child mechanism = %q", inc.Mechanism)
	}
	if len(inc.Children) == 0 {
		t.Fatal("include not expanded")
	}
	if inc.Children[0].Mechanism != "include" {
		t.Fatalf("nested mechanism = %q", inc.Children[0].Mechanism)
	}
	if len(inc.Children[0].Children) == 0 {
		t.Fatal("nested include not expanded")
	}
}

func TestAnalyzeSPF_MacroNotRecursed(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 exists:%{ir}.spf.example.com include:%{d}.spf.example.com -all")

	a := AnalyzeSPF("example.com", stub.fn())

	// Both macro terms count, neither expanded.
	if a.LookupCount != 2 {
		t.Fatalf("LookupCount = %d, want 2", a.LookupCount)
	}
	for _, c := range a.Root.Children {
		if c.CountsLookup && !c.Unresolved {
			t.Fatalf("term %q expected Unresolved=true", c.Term)
		}
	}
	// Should not have queried macro targets.
	if stub.calls["%{ir}.spf.example.com"] != 0 || stub.calls["%{d}.spf.example.com"] != 0 {
		t.Fatalf("macro targets were queried: %v", stub.calls)
	}
}

func TestAnalyzeSPF_CycleDetection(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 include:loop.example.com -all").
		set("loop.example.com", "v=spf1 include:example.com -all")

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 2 {
		t.Fatalf("LookupCount = %d, want 2", a.LookupCount)
	}
	cycleNode := a.Root.Children[0].Children[0]
	if cycleNode.Mechanism != "include" || cycleNode.Target != "example.com" {
		t.Fatalf("unexpected cycle node: %+v", cycleNode)
	}
	if cycleNode.Error != "cycle" {
		t.Fatalf("cycle node Error = %q, want %q", cycleNode.Error, "cycle")
	}
}

func TestAnalyzeSPF_VoidLookups(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 include:gone.example.com include:empty.example.com include:also-gone.example.com -all").
		void("empty.example.com")
	// gone and also-gone deliberately not in stub → NXDOMAIN-style void

	a := AnalyzeSPF("example.com", stub.fn())

	if a.VoidCount != 3 {
		t.Fatalf("VoidCount = %d, want 3", a.VoidCount)
	}
	if !a.OverVoidLimit {
		t.Fatal("OverVoidLimit not set")
	}
}

func TestAnalyzeSPF_OverLimit(t *testing.T) {
	// 11 includes pointing at terminal records → 11 lookups.
	root := strings.Builder{}
	root.WriteString("v=spf1")
	stub := newStub()
	for i := 0; i < 11; i++ {
		d := "leaf" + string(rune('a'+i)) + ".example.com"
		root.WriteString(" include:" + d)
		stub.set(d, "v=spf1 -all")
	}
	root.WriteString(" -all")
	stub.set("example.com", root.String())

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 11 {
		t.Fatalf("LookupCount = %d, want 11", a.LookupCount)
	}
	if !a.OverLimit {
		t.Fatal("OverLimit not set for 11 lookups")
	}
}

func TestAnalyzeSPF_MultipleRootRecords(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 ip4:1.2.3.4 -all", "v=spf1 ip4:5.6.7.8 -all")

	a := AnalyzeSPF("example.com", stub.fn())

	if !a.Multiple {
		t.Fatal("Multiple not set")
	}
	if len(a.Records) != 2 {
		t.Fatalf("Records = %d, want 2", len(a.Records))
	}
}

func TestAnalyzeSPF_NoRecord(t *testing.T) {
	stub := newStub().void("example.com")

	a := AnalyzeSPF("example.com", stub.fn())

	if a.Root != nil {
		t.Fatal("Root should be nil when no SPF record")
	}
	if a.LookupCount != 0 {
		t.Fatalf("LookupCount = %d, want 0", a.LookupCount)
	}
}

func TestAnalyzeSPF_RootFetchError(t *testing.T) {
	stub := newStub().fail("example.com", errors.New("connection refused"))

	a := AnalyzeSPF("example.com", stub.fn())

	if len(a.Errors) != 1 || !strings.Contains(a.Errors[0], "connection refused") {
		t.Fatalf("Errors = %v", a.Errors)
	}
}

func TestAnalyzeSPF_IncludeFetchError(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 include:broken.example.com -all").
		fail("broken.example.com", errors.New("timeout"))

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 1 {
		t.Fatalf("LookupCount = %d, want 1", a.LookupCount)
	}
	got := a.Root.Children[0]
	if got.Error == "" || !strings.Contains(got.Error, "timeout") {
		t.Fatalf("expected timeout error, got %q", got.Error)
	}
	// Errored include should not increment void counter.
	if a.VoidCount != 0 {
		t.Fatalf("VoidCount = %d, want 0", a.VoidCount)
	}
}

func TestAnalyzeSPF_IncludeMultipleRecords(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 include:dupes.example.com -all").
		set("dupes.example.com", "v=spf1 -all", "v=spf1 ip4:1.2.3.4 -all")

	a := AnalyzeSPF("example.com", stub.fn())

	got := a.Root.Children[0]
	if got.Error != "multiple SPF records" {
		t.Fatalf("Error = %q, want %q", got.Error, "multiple SPF records")
	}
}

func TestParseSPFTerm_Mechanisms(t *testing.T) {
	tests := []struct {
		in           string
		mech         string
		qual         string
		target       string
		countsLookup bool
		unresolved   bool
	}{
		{"+ip4:1.2.3.4", "ip4", "+", "1.2.3.4", false, false},
		{"-all", "all", "-", "", false, false},
		{"~all", "all", "~", "", false, false},
		{"?all", "all", "?", "", false, false},
		{"include:_spf.google.com", "include", "", "_spf.google.com", true, false},
		{"a", "a", "", "", true, false},
		{"a:mail.example.com", "a", "", "mail.example.com", true, false},
		{"a/24", "a", "", "/24", true, false},
		{"mx", "mx", "", "", true, false},
		{"ptr:example.com", "ptr", "", "example.com", true, false},
		{"exists:%{i}._spf.mta.salesforce.com", "exists", "", "%{i}._spf.mta.salesforce.com", true, true},
		{"redirect=spf.example.com", "redirect", "", "spf.example.com", true, false},
		{"exp=explain.example.com", "exp", "", "explain.example.com", false, false},
	}
	for _, tt := range tests {
		got := parseSPFTerm(tt.in)
		if got.Mechanism != tt.mech {
			t.Errorf("%q: Mechanism = %q, want %q", tt.in, got.Mechanism, tt.mech)
		}
		if got.Qualifier != tt.qual {
			t.Errorf("%q: Qualifier = %q, want %q", tt.in, got.Qualifier, tt.qual)
		}
		if got.Target != tt.target {
			t.Errorf("%q: Target = %q, want %q", tt.in, got.Target, tt.target)
		}
		if got.CountsLookup != tt.countsLookup {
			t.Errorf("%q: CountsLookup = %v, want %v", tt.in, got.CountsLookup, tt.countsLookup)
		}
		if got.Unresolved != tt.unresolved {
			t.Errorf("%q: Unresolved = %v, want %v", tt.in, got.Unresolved, tt.unresolved)
		}
	}
}

func TestAnalyzeSPF_DeepNesting(t *testing.T) {
	// Chain of single includes to verify depth limit triggers an error rather
	// than runaway recursion.
	stub := newStub()
	stub.set("d0.example.com", "v=spf1 include:d1.example.com -all")
	for i := 1; i <= spfDepthLimit+2; i++ {
		from := "d" + itoa(i) + ".example.com"
		next := "d" + itoa(i+1) + ".example.com"
		stub.set(from, "v=spf1 include:"+next+" -all")
	}
	stub.set("d"+itoa(spfDepthLimit+3)+".example.com", "v=spf1 -all")

	a := AnalyzeSPF("d0.example.com", stub.fn())

	hasDepthErr := false
	for _, e := range a.Errors {
		if strings.Contains(e, "max SPF depth") {
			hasDepthErr = true
			break
		}
	}
	if !hasDepthErr {
		t.Fatalf("expected max-depth error, got %v", a.Errors)
	}
}

func TestAnalyzeSPF_RedirectIgnoredWhenAllPresent(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 -all redirect=fallback.example.com").
		set("fallback.example.com", "v=spf1 ip4:1.2.3.4 -all")

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 0 {
		t.Fatalf("LookupCount = %d, want 0 (redirect ignored when all is present)", a.LookupCount)
	}
	if stub.calls["fallback.example.com"] != 0 {
		t.Fatalf("redirect target was queried despite all mechanism present")
	}
	// redirect node should be flagged Ignored.
	var redirect *SPFNode
	for _, c := range a.Root.Children {
		if c.Mechanism == "redirect" {
			redirect = c
			break
		}
	}
	if redirect == nil || !redirect.Ignored {
		t.Fatalf("redirect node not flagged Ignored: %+v", redirect)
	}
}

func TestAnalyzeSPF_AllItselfNotIgnored(t *testing.T) {
	// The matching `all` mechanism is the terminating action — it is evaluated,
	// not ignored. Only mechanisms textually after it should be flagged.
	stub := newStub().
		set("example.com", "v=spf1 ip4:1.2.3.4 -all")

	a := AnalyzeSPF("example.com", stub.fn())

	for _, c := range a.Root.Children {
		if c.Mechanism == "all" && c.Ignored {
			t.Fatalf("all mechanism flagged Ignored: %+v", c)
		}
	}
}

func TestAnalyzeSPF_ExpAfterAllNotIgnored(t *testing.T) {
	// exp= is a modifier that applies on fail results regardless of position.
	// It must not be flagged Ignored just because it appears after `all`.
	stub := newStub().
		set("example.com", "v=spf1 ip4:1.2.3.4 -all exp=explain.example.com")

	a := AnalyzeSPF("example.com", stub.fn())

	var exp *SPFNode
	for _, c := range a.Root.Children {
		if c.Mechanism == "exp" {
			exp = c
			break
		}
	}
	if exp == nil {
		t.Fatal("exp node not present")
	}
	if exp.Ignored {
		t.Fatalf("exp flagged Ignored: %+v", exp)
	}
}

func TestAnalyzeSPF_RootTrailingDotCycle(t *testing.T) {
	// Root passed with a trailing dot must still be recognized as a cycle
	// when a child includes the same domain without the dot.
	stub := newStub().
		set("example.com", "v=spf1 include:example.com -all")

	a := AnalyzeSPF("example.com.", stub.fn())

	if a.LookupCount != 1 {
		t.Fatalf("LookupCount = %d, want 1", a.LookupCount)
	}
	child := a.Root.Children[0]
	if child.Error != "cycle" {
		t.Fatalf("expected cycle on root self-include, got Error=%q", child.Error)
	}
}

func TestAnalyzeSPF_TermsAfterAllIgnored(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 ip4:1.2.3.4 -all include:should-not-count.example.com a:mail.example.com")

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 0 {
		t.Fatalf("LookupCount = %d, want 0 (terms after all ignored)", a.LookupCount)
	}
	if stub.calls["should-not-count.example.com"] != 0 {
		t.Fatalf("term after all was queried")
	}
	var inc, after *SPFNode
	for _, c := range a.Root.Children {
		switch c.Term {
		case "include:should-not-count.example.com":
			inc = c
		case "a:mail.example.com":
			after = c
		}
	}
	if inc == nil || !inc.Ignored {
		t.Fatalf("include after all not Ignored: %+v", inc)
	}
	if after == nil || !after.Ignored {
		t.Fatalf("a after all not Ignored: %+v", after)
	}
}

func TestAnalyzeSPF_RepeatedIncludeNoFalseCycle(t *testing.T) {
	// Same include used in two sibling positions should both be expanded —
	// not flagged as a cycle. Path-scoped visited set required.
	stub := newStub().
		set("example.com", "v=spf1 include:_spf.shared.com include:_spf.shared.com -all").
		set("_spf.shared.com", "v=spf1 ip4:1.2.3.4 -all")

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 2 {
		t.Fatalf("LookupCount = %d, want 2", a.LookupCount)
	}
	for i, c := range a.Root.Children {
		if c.Mechanism != "include" {
			continue
		}
		if c.Error == "cycle" {
			t.Fatalf("child %d falsely flagged as cycle", i)
		}
		if len(c.Children) == 0 {
			t.Fatalf("child %d not expanded", i)
		}
	}
}

func TestAnalyzeSPF_RealCycleStillDetected(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 include:loop.example.com -all").
		set("loop.example.com", "v=spf1 include:example.com -all")

	a := AnalyzeSPF("example.com", stub.fn())

	cycleNode := a.Root.Children[0].Children[0]
	if cycleNode.Error != "cycle" {
		t.Fatalf("expected cycle, got %q", cycleNode.Error)
	}
}

func TestAnalyzeSPF_RedirectChain(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 redirect=a.example.com").
		set("a.example.com", "v=spf1 redirect=b.example.com").
		set("b.example.com", "v=spf1 ip4:1.2.3.4 -all")

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 2 {
		t.Fatalf("LookupCount = %d, want 2", a.LookupCount)
	}
	first := a.Root.Children[0]
	if first.Mechanism != "redirect" || len(first.Children) == 0 {
		t.Fatalf("redirect not expanded: %+v", first)
	}
	second := first.Children[0]
	if second.Mechanism != "redirect" || len(second.Children) == 0 {
		t.Fatalf("nested redirect not expanded: %+v", second)
	}
}

func TestAnalyzeSPF_RootDomainTrailingDot(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 include:_spf.example.com -all").
		set("_spf.example.com", "v=spf1 ip4:1.2.3.4 -all")

	a := AnalyzeSPF("example.com.", stub.fn())

	if a.LookupCount != 1 {
		t.Fatalf("LookupCount = %d, want 1", a.LookupCount)
	}
	if a.Root == nil || len(a.Root.Children) == 0 {
		t.Fatal("root not parsed")
	}
}

func TestAnalyzeSPF_QualifiedInclude(t *testing.T) {
	stub := newStub().
		set("example.com", "v=spf1 +include:plus.example.com ?include:question.example.com ~include:tilde.example.com -include:minus.example.com -all").
		set("plus.example.com", "v=spf1 -all").
		set("question.example.com", "v=spf1 -all").
		set("tilde.example.com", "v=spf1 -all").
		set("minus.example.com", "v=spf1 -all")

	a := AnalyzeSPF("example.com", stub.fn())

	if a.LookupCount != 4 {
		t.Fatalf("LookupCount = %d, want 4", a.LookupCount)
	}
	wantQuals := []string{"+", "?", "~", "-"}
	for i, q := range wantQuals {
		if a.Root.Children[i].Qualifier != q {
			t.Errorf("child %d qualifier = %q, want %q", i, a.Root.Children[i].Qualifier, q)
		}
		if a.Root.Children[i].Mechanism != "include" {
			t.Errorf("child %d mechanism = %q, want include", i, a.Root.Children[i].Mechanism)
		}
	}
}

// startSPFDNSServer spins up a UDP+TCP DNS server and returns its address.
// Each handler call serves whatever TXT records are configured for the
// queried name. Names not in the map return NXDOMAIN.
func startSPFDNSServer(t *testing.T, records map[string][]string) string {
	t.Helper()

	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := udpConn.LocalAddr().String()
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		_ = udpConn.Close()
		t.Fatal(err)
	}

	handler := mdns.HandlerFunc(func(w mdns.ResponseWriter, r *mdns.Msg) {
		m := new(mdns.Msg)
		m.SetReply(r)
		if len(r.Question) == 0 || r.Question[0].Qtype != mdns.TypeTXT {
			_ = w.WriteMsg(m)
			return
		}
		name := strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
		txts, ok := records[name]
		if !ok {
			m.Rcode = mdns.RcodeNameError
			_ = w.WriteMsg(m)
			return
		}
		for _, t := range txts {
			m.Answer = append(m.Answer, &mdns.TXT{
				Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: 60},
				Txt: []string{t},
			})
		}
		_ = w.WriteMsg(m)
	})

	udpServer := &mdns.Server{PacketConn: udpConn, Handler: handler, Net: "udp"}
	tcpServer := &mdns.Server{Listener: tcpLn, Handler: handler, Net: "tcp"}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return addr
}

// withSPFResolver swaps the package-level resolver lookup for the duration
// of t by setting QUIEN_RESOLVER, which findResolver() honors.
func withSPFResolver(t *testing.T, addr string) {
	t.Helper()
	t.Setenv("QUIEN_RESOLVER", addr)
}

func TestDefaultSPFLookup_FiltersNonSPFTXT(t *testing.T) {
	addr := startSPFDNSServer(t, map[string][]string{
		"example.com": {
			"some-other-txt-value",
			"v=spf1 ip4:1.2.3.4 -all",
			"v=DMARC1; p=reject", // wrong tag
			"v=spf10 -all",       // looks similar but not SPF
		},
	})
	withSPFResolver(t, addr)

	recs, void, err := defaultSPFLookup("example.com")
	if err != nil {
		t.Fatalf("defaultSPFLookup error: %v", err)
	}
	if void {
		t.Fatal("void = true, want false")
	}
	if len(recs) != 1 {
		t.Fatalf("recs = %v, want exactly the one v=spf1 record", recs)
	}
	if recs[0] != "v=spf1 ip4:1.2.3.4 -all" {
		t.Fatalf("unexpected record: %q", recs[0])
	}
}

func TestDefaultSPFLookup_NXDOMAINIsVoid(t *testing.T) {
	addr := startSPFDNSServer(t, map[string][]string{}) // nothing configured
	withSPFResolver(t, addr)

	recs, void, err := defaultSPFLookup("missing.example.com")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !void || recs != nil {
		t.Fatalf("recs=%v void=%v, want nil/true", recs, void)
	}
}

func TestDefaultSPFLookup_NoSPFTXTIsVoid(t *testing.T) {
	addr := startSPFDNSServer(t, map[string][]string{
		"example.com": {"v=DMARC1; p=reject"},
	})
	withSPFResolver(t, addr)

	recs, void, err := defaultSPFLookup("example.com")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !void || recs != nil {
		t.Fatalf("recs=%v void=%v, want nil/true", recs, void)
	}
}

func TestDefaultSPFLookup_MultipleSPFRecords(t *testing.T) {
	addr := startSPFDNSServer(t, map[string][]string{
		"example.com": {
			"v=spf1 ip4:1.2.3.4 -all",
			"v=spf1 ip4:5.6.7.8 -all",
		},
	})
	withSPFResolver(t, addr)

	recs, void, err := defaultSPFLookup("example.com")
	if err != nil || void {
		t.Fatalf("err=%v void=%v", err, void)
	}
	if len(recs) != 2 {
		t.Fatalf("recs = %d, want 2", len(recs))
	}
}

func TestIsSPFRecord(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"v=spf1", true},
		{"v=spf1 -all", true},
		{"v=spf1\t-all", true},
		{"v=spf10 -all", false},
		{"v=spf1foo", false},
		{"V=spf1 -all", true}, // version is case-insensitive per RFC 7208 §12 ABNF
		{"", false},
		{"spf1", false},
	}
	for _, tt := range tests {
		if got := isSPFRecord(tt.in); got != tt.want {
			t.Errorf("isSPFRecord(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// itoa is a tiny helper to avoid pulling in strconv in test helpers.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

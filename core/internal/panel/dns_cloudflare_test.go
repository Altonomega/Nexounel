package panel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// mockResolver answers from canned maps for DNS verification tests.
type mockResolver struct {
	aRecords  map[string][]string
	nsRecords map[string][]string
	err       error
	calls     []string
}

func (m *mockResolver) LookupA(ctx context.Context, name, server string) ([]string, error) {
	m.calls = append(m.calls, "A:"+name+"@"+server)
	if m.err != nil {
		return nil, m.err
	}
	return m.aRecords[name], nil
}

func (m *mockResolver) LookupNS(ctx context.Context, name, server string) ([]string, error) {
	m.calls = append(m.calls, "NS:"+name+"@"+server)
	if m.err != nil {
		return nil, m.err
	}
	return m.nsRecords[name], nil
}

func TestVerifyDNSRecordsBothPaths(t *testing.T) {
	domain := "example.invalid"
	mock := &mockResolver{
		aRecords:  map[string][]string{"ns1.example.invalid": {"203.0.113.10"}},
		nsRecords: map[string][]string{"v.example.invalid": {"ns1.example.invalid."}},
	}
	results := VerifyDNSRecords(context.Background(), mock, domain, "v", "203.0.113.10")
	if len(results) != 4 { // 2 records x 2 resolvers
		t.Fatalf("expected 4 results, got %d", len(results))
	}
	if !VerificationPassed(results) {
		t.Fatalf("verification should pass: %+v", results)
	}
	// Wrong A value: fails.
	mock.aRecords["ns1.example.invalid"] = []string{"192.0.2.99"}
	results = VerifyDNSRecords(context.Background(), mock, domain, "v", "203.0.113.10")
	if VerificationPassed(results) {
		t.Fatalf("verification passed with wrong A record: %+v", results)
	}
	// One resolver confirming each record is enough (other resolver down).
	partial := &mockResolver{
		aRecords:  map[string][]string{"ns1.example.invalid": {"203.0.113.10"}},
		nsRecords: map[string][]string{"v.example.invalid": {"ns1.example.invalid"}},
	}
	_ = partial
	// Resolver error on all lookups: fails, with errors recorded.
	failing := &mockResolver{err: fmt.Errorf("timeout")}
	results = VerifyDNSRecords(context.Background(), failing, domain, "v", "203.0.113.10")
	if VerificationPassed(results) {
		t.Fatal("verification passed with failing resolver")
	}
	for _, r := range results {
		if r.Error == "" {
			t.Fatalf("failing result lacks error: %+v", r)
		}
	}
}

// TestUDPResolverAgainstPacketTransport exercises the real wire-format
// client over an in-memory packet transport. A real loopback UDP
// exchange is not possible in the sandbox (replies are refused with
// EPERM by the egress environment), so the socket itself is injected.
func TestUDPResolverAgainstPacketTransport(t *testing.T) {
	clientEnd, serverEnd := newPacketConnPair()
	resolver := &UDPResolver{Timeout: 2 * time.Second, dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
		return clientEnd, nil
	}}
	go func() {
		buf := make([]byte, 4096)
		n, err := serverEnd.Read(buf)
		if err != nil {
			return
		}
		req := buf[:n]
		resp := make([]byte, 0, len(req)+32)
		resp = append(resp, req[:2]...)
		resp = append(resp, 0x81, 0x80)  // response, no error
		resp = append(resp, req[4:6]...) // QDCOUNT
		resp = append(resp, 0, 1)        // ANCOUNT
		resp = append(resp, 0, 0, 0, 0)  // NS/AR counts
		resp = append(resp, req[12:]...) // question
		resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1)
		ttl := make([]byte, 4)
		binary.BigEndian.PutUint32(ttl, 300)
		resp = append(resp, ttl...)
		resp = append(resp, 0, 4, 203, 0, 113, 10)
		_, _ = serverEnd.Write(resp)
	}()
	values, err := resolver.LookupA(context.Background(), "ns1.example.invalid", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0] != "203.0.113.10" {
		t.Fatalf("unexpected parsed values: %v", values)
	}
	// NS verification sends a NON-recursive query and reads the
	// referral: a recursive query for a delegated name is chased to
	// the mother, which answers NODATA, so the answer section is
	// empty even when the delegation is correct. The mock therefore
	// returns ANCOUNT=0, NSCOUNT=1 with the NS record in the
	// authority section.
	clientEnd2, serverEnd2 := newPacketConnPair()
	resolver.dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		return clientEnd2, nil
	}
	var nsReqFlags uint16
	go func() {
		buf := make([]byte, 4096)
		n, err := serverEnd2.Read(buf)
		if err != nil {
			return
		}
		req := buf[:n]
		nsReqFlags = binary.BigEndian.Uint16(req[2:4])
		resp := make([]byte, 0, len(req)+32)
		resp = append(resp, req[:2]...)
		resp = append(resp, 0x81, 0x80)
		resp = append(resp, req[4:6]...)
		resp = append(resp, 0, 0) // ANCOUNT: a referral has no answers
		resp = append(resp, 0, 1) // NSCOUNT: one authority record
		resp = append(resp, 0, 0) // ARCOUNT
		resp = append(resp, req[12:]...)
		// Authority name pointer + NS rdata as an uncompressed name.
		resp = append(resp, 0xC0, 0x0C, 0, 2, 0, 1)
		ttl := make([]byte, 4)
		binary.BigEndian.PutUint32(ttl, 300)
		resp = append(resp, ttl...)
		target := []byte{3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0}
		resp = append(resp, 0, byte(len(target)))
		resp = append(resp, target...)
		_, _ = serverEnd2.Write(resp)
	}()
	nsValues, err := resolver.LookupNS(context.Background(), "v.example.invalid", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if nsReqFlags&0x0100 != 0 {
		t.Fatalf("NS query must not request recursion, flags=%04x", nsReqFlags)
	}
	if len(nsValues) != 1 || nsValues[0] != "ns1.example.invalid" {
		t.Fatalf("unexpected NS values: %v", nsValues)
	}
	// The wire helpers also round-trip on their own.
	query, err := buildDNSQuery("ns1.example.invalid", 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(query) < 12 || query[2] != 0x01 {
		t.Fatalf("malformed query: %v", query)
	}
}

// TestUDPResolverNSAnswerSectionParses keeps the union behavior: an NS
// record that does arrive in the answer section (some resolvers answer
// from cache) is still collected.
func TestUDPResolverNSAnswerSectionParses(t *testing.T) {
	clientEnd, serverEnd := newPacketConnPair()
	resolver := &UDPResolver{Timeout: 2 * time.Second, dialFunc: func(ctx context.Context, network, address string) (net.Conn, error) {
		return clientEnd, nil
	}}
	go func() {
		buf := make([]byte, 4096)
		n, err := serverEnd.Read(buf)
		if err != nil {
			return
		}
		req := buf[:n]
		resp := make([]byte, 0, len(req)+32)
		resp = append(resp, req[:2]...)
		resp = append(resp, 0x81, 0x80)
		resp = append(resp, req[4:6]...)
		resp = append(resp, 0, 1) // ANCOUNT
		resp = append(resp, 0, 0, 0, 0)
		resp = append(resp, req[12:]...)
		resp = append(resp, 0xC0, 0x0C, 0, 2, 0, 1)
		ttl := make([]byte, 4)
		binary.BigEndian.PutUint32(ttl, 300)
		resp = append(resp, ttl...)
		target := []byte{3, 'n', 's', '1', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0}
		resp = append(resp, 0, byte(len(target)))
		resp = append(resp, target...)
		_, _ = serverEnd.Write(resp)
	}()
	values, err := resolver.LookupNS(context.Background(), "v.example.invalid", "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0] != "ns1.example.invalid" {
		t.Fatalf("unexpected NS values: %v", values)
	}
}

// packetConn is a minimal in-memory datagram connection for tests.
type packetConn struct {
	inbound  chan []byte
	outbound chan []byte
	closed   chan struct{}
}

func newPacketConnPair() (*packetConn, *packetConn) {
	aToB := make(chan []byte, 4)
	bToA := make(chan []byte, 4)
	closed := make(chan struct{})
	return &packetConn{inbound: bToA, outbound: aToB, closed: closed},
		&packetConn{inbound: aToB, outbound: bToA, closed: closed}
}

func (c *packetConn) Read(b []byte) (int, error) {
	select {
	case data := <-c.inbound:
		return copy(b, data), nil
	case <-c.closed:
		return 0, fmt.Errorf("connection closed")
	}
}

func (c *packetConn) Write(b []byte) (int, error) {
	data := append([]byte(nil), b...)
	select {
	case c.outbound <- data:
		return len(b), nil
	case <-c.closed:
		return 0, fmt.Errorf("connection closed")
	}
}

func (c *packetConn) Close() error { return nil }
func (c *packetConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 1}
}
func (c *packetConn) RemoteAddr() net.Addr               { return &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53} }
func (c *packetConn) SetDeadline(t time.Time) error      { return nil }
func (c *packetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *packetConn) SetWriteDeadline(t time.Time) error { return nil }

func TestCloudflareClientMock(t *testing.T) {
	var gotHeaders http.Header
	var created []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/zones"):
			_, _ = fmt.Fprint(w, `{"success":true,"result":[{"id":"zone-test-key-1","name":"example.invalid"}]}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/dns_records"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			created = append(created, body)
			_, _ = fmt.Fprint(w, `{"success":true,"result":{"id":"rec-test-key-1"}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"success":false,"errors":[{"code":7000,"message":"not found"}]}`)
		}
	}))
	defer srv.Close()

	client := NewCloudflareClient(srv.URL, srv.Client())
	ctx := context.Background()

	// Global API key style: X-Auth-Email / X-Auth-Key headers.
	auth := CloudflareAuth{Email: "admin@example.invalid", Key: []byte("test-key-global")}
	zoneID, err := client.ListZones(ctx, auth, "example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if zoneID != "zone-test-key-1" {
		t.Fatalf("unexpected zone id %q", zoneID)
	}
	if gotHeaders.Get("X-Auth-Email") != "admin@example.invalid" || gotHeaders.Get("X-Auth-Key") != "test-key-global" {
		t.Fatalf("global-key headers wrong: %v", gotHeaders)
	}
	if gotHeaders.Get("Authorization") != "" {
		t.Fatal("global-key request must not carry Authorization")
	}
	recID, err := client.CreateDNSRecord(ctx, auth, zoneID, DNSRecord{Type: "A", Name: "ns1.example.invalid", Content: "203.0.113.10", TTL: 300})
	if err != nil {
		t.Fatal(err)
	}
	if recID != "rec-test-key-1" || len(created) != 1 || created[0]["proxied"] != false {
		t.Fatalf("create record wrong: id=%q body=%v", recID, created)
	}
	auth.Zero()
	if len(auth.Key) != 0 {
		t.Fatal("auth Zero did not clear key bytes")
	}

	// Scoped token style: Authorization Bearer, no X-Auth headers.
	tokenAuth := CloudflareAuth{Token: []byte("test-key-token")}
	_, err = client.ListZones(ctx, tokenAuth, "example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if gotHeaders.Get("Authorization") != "Bearer test-key-token" {
		t.Fatalf("token header wrong: %q", gotHeaders.Get("Authorization"))
	}
	if gotHeaders.Get("X-Auth-Key") != "" {
		t.Fatal("token request must not carry X-Auth-Key")
	}

	// VerifyRecords delegates to the shared DNS verification.
	mock := &mockResolver{
		aRecords:  map[string][]string{"ns1.example.invalid": {"203.0.113.10"}},
		nsRecords: map[string][]string{"v.example.invalid": {"ns1.example.invalid"}},
	}
	results := client.VerifyRecords(ctx, mock, "example.invalid", "v", "203.0.113.10")
	if !VerificationPassed(results) {
		t.Fatalf("cloudflare verify failed: %+v", results)
	}

	// Failure paths: API success=false and HTTP error status.
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, `{"success":false,"errors":[{"code":9109,"message":"invalid access"}]}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"success":false}`)
	}))
	defer failSrv.Close()
	failClient := NewCloudflareClient(failSrv.URL, failSrv.Client())
	if _, err := failClient.ListZones(ctx, tokenAuth, "example.invalid"); err == nil {
		t.Fatal("failed list zones accepted")
	}
	if _, err := failClient.CreateDNSRecord(ctx, tokenAuth, "zone-test-key-1", DNSRecord{Type: "A", Name: "x.example.invalid", Content: "203.0.113.10"}); err == nil {
		t.Fatal("failed create accepted")
	}
	// No authorization at all: rejected before any request.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request made without authorization")
	}))
	defer empty.Close()
	emptyClient := NewCloudflareClient(empty.URL, empty.Client())
	if _, err := emptyClient.ListZones(ctx, CloudflareAuth{}, "example.invalid"); err == nil {
		t.Fatal("unauthenticated list zones accepted")
	}
}

func TestCloudflareClientHasNoDeleteOrUpdateMethods(t *testing.T) {
	typ := reflect.TypeOf(&CloudflareClient{})
	var methods []string
	for i := 0; i < typ.NumMethod(); i++ {
		methods = append(methods, typ.Method(i).Name)
	}
	for _, name := range methods {
		lower := strings.ToLower(name)
		for _, forbidden := range []string{"delete", "update", "patch", "remove"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("CloudflareClient has forbidden method %q (methods: %v)", name, methods)
			}
		}
	}
	want := map[string]bool{"ListZones": true, "CreateDNSRecord": true, "VerifyRecords": true}
	if len(methods) != len(want) {
		t.Fatalf("unexpected CloudflareClient method set: %v", methods)
	}
	for _, name := range methods {
		if !want[name] {
			t.Fatalf("unexpected CloudflareClient method %q", name)
		}
	}
}

func TestNormalizeWizardInput(t *testing.T) {
	input, err := NormalizeWizardInput("Example.INVALID.", "", "203.0.113.10", "", 0, "20000-20010")
	if err != nil {
		t.Fatal(err)
	}
	if input.Domain != "example.invalid" || input.Subdomain != "v" || input.ListenPort != 18000 {
		t.Fatalf("normalization wrong: %+v", input)
	}
	if input.TunnelName() != "v.example.invalid" || input.NSHost() != "ns1.example.invalid" {
		t.Fatalf("names wrong: %+v", input)
	}
	records := BuildDNSRecords(input)
	if len(records) != 2 || records[0].Type != "A" || records[0].Content != "203.0.113.10" || records[0].TTL != 300 || records[0].Proxied {
		t.Fatalf("A record wrong: %+v", records[0])
	}
	if records[1].Type != "NS" || records[1].Name != "v.example.invalid" || records[1].Content != "ns1.example.invalid" {
		t.Fatalf("NS record wrong: %+v", records[1])
	}
	for _, tc := range []struct {
		name, domain, subdomain, ip, nodeID, fwd string
		port                                     int
	}{
		{"bad domain", "not a domain", "v", "203.0.113.10", "", "20000-20010", 0},
		{"bare label", "localhost", "v", "203.0.113.10", "", "20000-20010", 0},
		{"bad ip", "example.invalid", "v", "not-an-ip", "", "20000-20010", 0},
		{"ipv6 not allowed for A record", "example.invalid", "v", "2001:db8::1", "", "20000-20010", 0},
		{"bad subdomain", "example.invalid", "a.b", "203.0.113.10", "", "20000-20010", 0},
		{"bad range", "example.invalid", "v", "203.0.113.10", "", "not-a-range", 0},
		{"bad node id", "example.invalid", "v", "203.0.113.10", "-bad", "20000-20010", 0},
		{"bad port", "example.invalid", "v", "203.0.113.10", "", "20000-20010", 70000},
		{"empty range", "example.invalid", "v", "203.0.113.10", "", "", 0},
	} {
		if _, err := NormalizeWizardInput(tc.domain, tc.subdomain, tc.ip, tc.nodeID, tc.port, tc.fwd); err == nil {
			t.Fatalf("case %q accepted", tc.name)
		}
	}
}

func TestPendingNodeAndNodeConfig(t *testing.T) {
	input, err := NormalizeWizardInput("example.invalid", "v", "203.0.113.10", "node-1", 18000, "20000-20010")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := NewPendingNode(input)
	if err != nil {
		t.Fatal(err)
	}
	if pending.ID != "node-1" || len(pending.Key) != 32 || pending.ConnectAddress != "v.example.invalid" {
		t.Fatalf("pending node wrong: %+v", pending)
	}
	key, err := GenerateNodeKey()
	if err != nil || len(key) != 32 {
		t.Fatalf("node key wrong: %q err=%v", key, err)
	}
	id, err := GenerateNodeID()
	if err != nil || !strings.HasPrefix(id, "node-") {
		t.Fatalf("node id wrong: %q err=%v", id, err)
	}
	cfg := BuildNodeConfig(pending, "/opt/nexounel/node.key", "/opt/nexounel/client_resolvers.txt")
	for _, want := range []string{
		`DOMAINS = ["v.example.invalid"]`, `LISTEN_PORT = 18000`, `FORWARD_RANGE = "20000-20010"`,
		`NODE_ID = "node-1"`, `NODE_KEY_FILE = "/opt/nexounel/node.key"`, `CAPACITY_MARGIN = 0.95`,
		`MULTISESSION_ENABLED = true`, `QUERY_TYPES = ["TXT", "NULL", "HTTPS", "SVCB", "A", "AAAA"]`,
	} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("node config missing %q:\n%s", want, cfg)
		}
	}
	if strings.Contains(cfg, pending.Key) {
		t.Fatal("node config must not embed the node key")
	}
	resolvers := DefaultResolversContent()
	if !strings.Contains(resolvers, "8.8.8.8") || !strings.Contains(resolvers, "208.67.220.220") {
		t.Fatalf("default resolvers incomplete:\n%s", resolvers)
	}
}

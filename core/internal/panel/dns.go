package panel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// DNSResolver resolves DNS records against an explicit resolver server.
// The production implementation speaks plain DNS over UDP; tests use a mock.
type DNSResolver interface {
	LookupNS(ctx context.Context, name, server string) ([]string, error)
	LookupA(ctx context.Context, name, server string) ([]string, error)
}

// PublicResolvers are the explicit public resolvers verification queries
// go to. They are fixed by the spec, not configurable, so verification
// never depends on the local resolver.
var PublicResolvers = []string{"8.8.8.8", "1.1.1.1"}

// RecordVerification is the per-resolver, per-record outcome of a DNS check.
type RecordVerification struct {
	Record   string // "A" or "NS"
	Name     string
	Expected string
	Resolver string
	Got      []string
	OK       bool
	Error    string
}

// VerifyDNSRecords checks both wizard records against every public
// resolver and returns one result per (record, resolver) pair.
func VerifyDNSRecords(ctx context.Context, resolver DNSResolver, domain, subdomain, motherIP string) []RecordVerification {
	nsName := "ns1." + domain
	tunnelName := subdomain + "." + domain
	var results []RecordVerification
	for _, server := range PublicResolvers {
		a, err := resolver.LookupA(ctx, nsName, server)
		results = append(results, RecordVerification{
			Record: "A", Name: nsName, Expected: motherIP, Resolver: server,
			Got: a, OK: err == nil && containsValue(a, motherIP), Error: errorString(err),
		})
		ns, err := resolver.LookupNS(ctx, tunnelName, server)
		results = append(results, RecordVerification{
			Record: "NS", Name: tunnelName, Expected: nsName, Resolver: server,
			Got: ns, OK: err == nil && containsName(ns, nsName), Error: errorString(err),
		})
	}
	return results
}

// VerificationPassed reports whether every record type was confirmed by
// at least one public resolver.
func VerificationPassed(results []RecordVerification) bool {
	seen := map[string]bool{}
	for _, r := range results {
		if r.OK {
			seen[r.Record] = true
		}
	}
	return seen["A"] && seen["NS"]
}

func containsValue(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func containsName(values []string, want string) bool {
	want = strings.TrimSuffix(strings.ToLower(want), ".")
	for _, v := range values {
		if strings.TrimSuffix(strings.ToLower(v), ".") == want {
			return true
		}
	}
	return false
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// UDPResolver is a minimal dependency-free DNS client over UDP.
type UDPResolver struct {
	Timeout time.Duration
	// dialFunc overrides dialing in tests (in-memory packet transport).
	dialFunc func(ctx context.Context, network, address string) (net.Conn, error)
}

// NewUDPResolver returns a UDP resolver with a 5s default timeout.
func NewUDPResolver() *UDPResolver { return &UDPResolver{Timeout: 5 * time.Second} }

func (r *UDPResolver) timeout() time.Duration {
	if r.Timeout <= 0 {
		return 5 * time.Second
	}
	return r.Timeout
}

// LookupA queries type A for name at the given resolver IP. The query
// asks for recursion: the answer section carries the record.
func (r *UDPResolver) LookupA(ctx context.Context, name, server string) ([]string, error) {
	return r.query(ctx, name, server, 1, true)
}

// LookupNS queries type NS for name at the given resolver IP WITHOUT
// recursion. A delegation can only be verified from the referral: a
// recursive query for the delegated name is chased to the mother
// itself, which answers NODATA (SOA) for its own NS records, so the
// answer section is empty even when the delegation is correct. With
// recursion disabled the resolver returns the referral, whose NS
// records live in the authority section.
func (r *UDPResolver) LookupNS(ctx context.Context, name, server string) ([]string, error) {
	return r.query(ctx, name, server, 2, false)
}

func (r *UDPResolver) query(ctx context.Context, name, server string, qtype uint16, recursion bool) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	msg, err := buildDNSQuery(name, qtype, recursion)
	if err != nil {
		return nil, err
	}
	dialer := net.Dialer{Timeout: r.timeout()}
	target := server
	if !strings.Contains(server, ":") {
		target = net.JoinHostPort(server, "53")
	}
	dial := r.dialFunc
	if dial == nil {
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "udp", target)
	if err != nil {
		return nil, fmt.Errorf("dial resolver %s: %w", server, err)
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(r.timeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("send DNS query to %s: %w", server, err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read DNS response from %s: %w", server, err)
	}
	return parseDNSResponse(buf[:n], qtype, qtype == 2)
}

func buildDNSQuery(name string, qtype uint16, recursion bool) ([]byte, error) {
	id := uint16(rand.Uint32())
	msg := make([]byte, 0, 64)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	flags := uint16(0x0000)
	if recursion {
		flags = 0x0100 // recursion desired
	}
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT
	msg = append(msg, header...)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label in %q", name)
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	msg = append(msg, tail[:]...)
	return msg, nil
}

// parseDNSName decodes a possibly-compressed domain name at offset.
func parseDNSName(msg []byte, offset int) (string, int, error) {
	return parseDNSNameDepth(msg, offset, 0)
}

func parseDNSNameDepth(msg []byte, offset int, depth int) (string, int, error) {
	if depth > 8 {
		return "", 0, errors.New("DNS compression pointer chain too deep")
	}
	var labels []string
	next := offset
	jumped := false
	for hops := 0; hops < 128; hops++ {
		if next >= len(msg) {
			return "", 0, errors.New("DNS name overruns message")
		}
		length := int(msg[next])
		if length == 0 {
			next++
			break
		}
		if length&0xC0 == 0xC0 {
			if next+1 >= len(msg) {
				return "", 0, errors.New("truncated DNS compression pointer")
			}
			pointer := int(binary.BigEndian.Uint16(msg[next:next+2]) & 0x3FFF)
			if !jumped {
				next += 2
			}
			jumped = true
			// Follow the pointer from its target; the caller's next
			// offset is already the position after the pointer.
			target, _, err := parseDNSNameDepth(msg, pointer, depth+1)
			if err != nil {
				return "", 0, err
			}
			if target != "" {
				labels = append(labels, target)
			}
			break
		}
		if length&0xC0 != 0 {
			return "", 0, errors.New("invalid DNS label length")
		}
		next++
		if next+length > len(msg) {
			return "", 0, errors.New("DNS label overruns message")
		}
		labels = append(labels, string(msg[next:next+length]))
		next += length
	}
	if !jumped {
		return strings.Join(labels, "."), next, nil
	}
	return strings.Join(labels, "."), next, nil
}

func parseDNSResponse(msg []byte, wantType uint16, includeAuthority bool) ([]string, error) {
	if len(msg) < 12 {
		return nil, errors.New("DNS response too short")
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("DNS response is not a response")
	}
	if rcode := flags & 0x000F; rcode != 0 {
		return nil, fmt.Errorf("DNS server returned error code %d", rcode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	nsCount := int(binary.BigEndian.Uint16(msg[8:10]))
	offset := 12
	for i := 0; i < qdCount; i++ {
		_, next, err := parseDNSName(msg, offset)
		if err != nil {
			return nil, err
		}
		offset = next + 4
		if offset > len(msg) {
			return nil, errors.New("DNS question overruns message")
		}
	}
	var values []string
	scan := func(count int) error {
		for i := 0; i < count; i++ {
			_, next, err := parseDNSName(msg, offset)
			if err != nil {
				return err
			}
			offset = next
			if offset+10 > len(msg) {
				return errors.New("DNS record overruns message")
			}
			rtype := binary.BigEndian.Uint16(msg[offset : offset+2])
			rdLen := int(binary.BigEndian.Uint16(msg[offset+8 : offset+10]))
			offset += 10
			if offset+rdLen > len(msg) {
				return errors.New("DNS rdata overruns message")
			}
			rdata := msg[offset : offset+rdLen]
			if rtype == wantType {
				switch wantType {
				case 1:
					if len(rdata) == 4 {
						values = append(values, net.IP(rdata).String())
					}
				case 2:
					target, _, err := parseDNSName(msg, offset)
					if err == nil {
						values = append(values, target)
					}
				}
			}
			offset += rdLen
		}
		return nil
	}
	if err := scan(anCount); err != nil {
		return nil, err
	}
	// Referrals carry the delegated NS records in the authority
	// section; answer-section records are preferred when present,
	// so both sections are collected for NS queries.
	if includeAuthority {
		if err := scan(nsCount); err != nil {
			return nil, err
		}
	}
	return values, nil
}

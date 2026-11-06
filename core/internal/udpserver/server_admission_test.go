package udpserver

import (
	"testing"

	"github.com/Altonomega/Nexounel/core/internal/config"
	DnsParser "github.com/Altonomega/Nexounel/core/internal/dnsparser"
	domainMatcher "github.com/Altonomega/Nexounel/core/internal/domainmatcher"
	Enums "github.com/Altonomega/Nexounel/core/internal/enums"
	"github.com/Altonomega/Nexounel/core/internal/security"
	VpnProto "github.com/Altonomega/Nexounel/core/internal/vpnproto"
)

func TestIngressQueueCapacityKeepsFullBurstWithinMemoryLimit(t *testing.T) {
	s := &Server{cfg: config.ServerConfig{
		MaxConcurrentRequests: 16384,
		MaxIngressQueueBytes:  64 * 1024 * 1024,
		MaxPacketSize:         4096,
	}}
	if got, want := s.ingressQueueCapacity(), 16384; got != want {
		t.Fatalf("ingressQueueCapacity() = %d, want %d", got, want)
	}
}

func TestIngressAdmissionRejectsNoiseBeforeQueue(t *testing.T) {
	codec, err := security.NewCodec(5, "shared-ingress-test-key")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		domainMatcher: domainMatcher.New([]string{"v.example.com"}, 3),
	}
	s.installed.Store(&codecSet{codecs: []*security.Codec{codec}})

	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID: 7, PacketType: Enums.PACKET_SESSION_INIT, SessionCookie: 9,
	}, codec)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := DnsParser.BuildTunnelTXTQuestionPacket("v.example.com", []byte(encoded), Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	if !s.admitIngressPacket(valid) {
		t.Fatal("valid keyed frame was rejected")
	}

	wrongDomain, err := DnsParser.BuildTunnelTXTQuestionPacket("other.example.com", []byte(encoded), Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	if s.admitIngressPacket(wrongDomain) {
		t.Fatal("query for an unrelated domain was admitted")
	}
	if s.admitIngressPacket([]byte("not dns")) {
		t.Fatal("malformed datagram was admitted")
	}

	wrongCodec, err := security.NewCodec(5, "attacker-key")
	if err != nil {
		t.Fatal(err)
	}
	wrongEncoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID: 7, PacketType: Enums.PACKET_SESSION_INIT, SessionCookie: 9,
	}, wrongCodec)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := DnsParser.BuildTunnelTXTQuestionPacket("v.example.com", []byte(wrongEncoded), Enums.DNS_RECORD_TYPE_TXT, 1232)
	if err != nil {
		t.Fatal(err)
	}
	if s.admitIngressPacket(wrongKey) {
		t.Fatal("frame made with the wrong shared key was admitted")
	}
}

func TestIngressAdmissionAcceptsConfiguredMethodOnly(t *testing.T) {
	const sharedKey = "configured-method-shared-key"
	preferred, err := security.NewCodec(5, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		domainMatcher: domainMatcher.New([]string{"v.example.com"}, 3),
	}
	s.installed.Store(&codecSet{codecs: []*security.Codec{preferred}})
	methods := []int{5}

	queryTypes := []uint16{
		Enums.DNS_RECORD_TYPE_A,
		Enums.DNS_RECORD_TYPE_AAAA,
		Enums.DNS_RECORD_TYPE_NULL,
		Enums.DNS_RECORD_TYPE_CNAME,
		Enums.DNS_RECORD_TYPE_MX,
		Enums.DNS_RECORD_TYPE_NS,
		Enums.DNS_RECORD_TYPE_PTR,
		Enums.DNS_RECORD_TYPE_SRV,
		Enums.DNS_RECORD_TYPE_SVCB,
		Enums.DNS_RECORD_TYPE_CAA,
		Enums.DNS_RECORD_TYPE_NAPTR,
		Enums.DNS_RECORD_TYPE_SOA,
		Enums.DNS_RECORD_TYPE_TXT,
		Enums.DNS_RECORD_TYPE_HTTPS,
	}
	normalized, qname, err := DnsParser.PrepareTunnelDomainQname("v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range methods {
		codec, codecErr := security.NewCodec(method, sharedKey)
		if codecErr != nil {
			t.Fatalf("method %d: %v", method, codecErr)
		}
		encoded, buildErr := VpnProto.BuildEncoded(VpnProto.BuildOptions{
			SessionID: 255, PacketType: Enums.PACKET_MTU_UP_REQ,
			Payload: []byte{0, 1, 2, 3, 4},
		}, codec)
		if buildErr != nil {
			t.Fatalf("method %d: %v", method, buildErr)
		}
		for _, qType := range queryTypes {
			query, queryErr := DnsParser.BuildTunnelQuestionPacketShaped(
				normalized,
				qname,
				[]byte(encoded),
				qType,
				DnsParser.QueryShaping{
					EDNSUDPSize:   4096,
					RandomizeID:   true,
					EDNSCookie:    true,
					CaseRandomize: true,
				},
			)
			if queryErr != nil {
				t.Fatalf("method %d qtype %s: %v", method, Enums.DNSRecordTypeName(qType), queryErr)
			}
			if !s.admitIngressPacket(query) {
				t.Fatalf("method %d qtype %s with shaped QNAME was rejected", method, Enums.DNSRecordTypeName(qType))
			}
		}
	}
	for _, method := range methods {
		if got := s.codecAccepted[method].Load(); got == 0 {
			t.Fatalf("method %d was accepted but not recorded", method)
		}
	}
}

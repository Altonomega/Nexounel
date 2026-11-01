package udpserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	DnsParser "github.com/MNSH-Nexo/Nexounel/core/internal/dnsparser"
	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
	"github.com/MNSH-Nexo/Nexounel/core/internal/logger"
	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
	VpnProto "github.com/MNSH-Nexo/Nexounel/core/internal/vpnproto"
)

func newSingleMethodTransportTestServer(t *testing.T, configuredMethod, method int) (*Server, []byte) {
	t.Helper()
	const sharedKey = "transport-matrix-shared-key"
	codec, err := security.NewCodec(configuredMethod, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	s := New(config.ServerConfig{
		Domain:                            []string{"v.example.com"},
		MinVPNLabelLength:                 3,
		SessionOrphanQueueInitialCap:      8,
		StreamQueueInitialCapacity:        8,
		DNSFragmentStoreCapacity:          8,
		SOCKS5FragmentStoreCapacity:       8,
		MaxStreamsPerSession:              16,
		MaxActiveSessions:                 16,
		DNSCacheMaxRecords:                16,
		DNSCacheTTLSeconds:                60,
		MaxPacketSize:                     4096,
		MaxPacketsPerBatch:                1,
		SupportedUploadCompressionTypes:   []int{0, 1, 2, 3},
		SupportedDownloadCompressionTypes: []int{0, 1, 2, 3},
	}, logger.New("transport-matrix-test", "ERROR"), codec)
	changedCodec, err := security.NewCodec(method, sharedKey)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		SessionID:  255,
		PacketType: Enums.PACKET_MTU_UP_REQ,
		Payload:    []byte{0, 1, 2, 3, 4},
	}, changedCodec)
	if err != nil {
		t.Fatal(err)
	}
	normalized, qname, err := DnsParser.PrepareTunnelDomainQname("v.example.com")
	if err != nil {
		t.Fatal(err)
	}
	query, err := DnsParser.BuildTunnelQuestionPacketShaped(normalized, qname, []byte(encoded), Enums.DNS_RECORD_TYPE_HTTPS, DnsParser.QueryShaping{
		EDNSUDPSize: 4096, RandomizeID: true, EDNSCookie: true, CaseRandomize: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, query
}

func assertDynamicMTUResponse(t *testing.T, response []byte) {
	t.Helper()
	packet, err := DnsParser.ExtractVPNResponseMatching(response, false, []string{"v.example.com"})
	if err != nil {
		t.Fatalf("extract dynamic MTU response: %v", err)
	}
	if packet.PacketType != Enums.PACKET_MTU_UP_RES {
		t.Fatalf("dynamic response packet type = %s, want MTU_UP_RES", Enums.PacketTypeName(packet.PacketType))
	}
	if len(packet.Payload) < mtuProbeCodeLength || !bytes.Equal(packet.Payload[:mtuProbeCodeLength], []byte{1, 2, 3, 4}) {
		t.Fatalf("dynamic response verification code = %v, want [1 2 3 4]", packet.Payload)
	}
}

func assertNoDynamicMTUResponse(t *testing.T, response []byte) {
	t.Helper()
	packet, err := DnsParser.ExtractVPNResponseMatching(response, false, []string{"v.example.com"})
	if err != nil {
		return // no VPN payload: the frame was rejected, as required
	}
	if packet.PacketType == Enums.PACKET_MTU_UP_RES {
		t.Fatalf("frame encrypted with a non-configured method produced a dynamic MTU response: %+v", packet)
	}
}

// TestSingleMethodAcrossTransportsAndOtherMethodsRejected pins the
// single-method security model: a server configured for one AES-GCM method
// answers frames encrypted with exactly that method on every transport, and
// frames encrypted with any other AES-GCM method are rejected (no valid
// response) instead of being trial-decrypted.
func TestSingleMethodAcrossTransportsAndOtherMethodsRejected(t *testing.T) {
	for _, configured := range []int{3, 4, 5} {
		configured := configured
		t.Run("configured-"+strconv.Itoa(configured), func(t *testing.T) {
			t.Run("matching-method", func(t *testing.T) {
				t.Run("UDP", func(t *testing.T) {
					s, query := newSingleMethodTransportTestServer(t, configured, configured)
					assertDynamicMTUResponse(t, s.safeHandlePacket(query))
				})

				t.Run("TCP", func(t *testing.T) {
					s, query := newSingleMethodTransportTestServer(t, configured, configured)
					client, server := net.Pipe()
					defer client.Close()
					go func() {
						serveTCPDNSMessages(context.Background(), server, s.safeHandlePacket)
						_ = server.Close()
					}()
					_ = client.SetDeadline(time.Now().Add(3 * time.Second))
					if err := writeTCPDNSMessage(client, query); err != nil {
						t.Fatal(err)
					}
					response, err := readTCPDNSMessage(client)
					if err != nil {
						t.Fatalf("TCP response: %v", err)
					}
					assertDynamicMTUResponse(t, response)
				})

				t.Run("DoT", func(t *testing.T) {
					s, query := newSingleMethodTransportTestServer(t, configured, configured)
					cert, err := generateSelfSignedCert([]string{"v.example.com"})
					if err != nil {
						t.Fatal(err)
					}
					clientRaw, serverRaw := net.Pipe()
					serverTLS := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"dot"}})
					clientTLS := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}) // test certificate
					defer clientTLS.Close()
					go func() {
						serveTCPDNSMessages(context.Background(), serverTLS, s.safeHandlePacket)
						_ = serverTLS.Close()
					}()
					_ = clientTLS.SetDeadline(time.Now().Add(3 * time.Second))
					if err := writeTCPDNSMessage(clientTLS, query); err != nil {
						t.Fatal(err)
					}
					response, err := readTCPDNSMessage(clientTLS)
					if err != nil {
						t.Fatalf("DoT response: %v", err)
					}
					assertDynamicMTUResponse(t, response)
					if got := clientTLS.ConnectionState().NegotiatedProtocol; got != "dot" {
						t.Fatalf("DoT ALPN = %q, want dot", got)
					}
				})

				t.Run("DoH", func(t *testing.T) {
					s, query := newSingleMethodTransportTestServer(t, configured, configured)
					req := httptest.NewRequest(http.MethodPost, "/dns-query", bytes.NewReader(query))
					req.Header.Set("Content-Type", dohContentType)
					response := httptest.NewRecorder()
					s.handleDoHRequest(response, req, dohMaxMessageSize)
					if response.Code != http.StatusOK || response.Body.Len() == 0 {
						t.Fatalf("DoH response: status=%d bytes=%d body=%q", response.Code, response.Body.Len(), response.Body.String())
					}
					if got := response.Header().Get("Content-Type"); got != dohContentType {
						t.Fatalf("DoH content type = %q", got)
					}
					assertDynamicMTUResponse(t, response.Body.Bytes())
				})
			})
			for _, other := range []int{3, 4, 5} {
				if other == configured {
					continue
				}
				t.Run("rejected-method-"+strconv.Itoa(other), func(t *testing.T) {
					s, query := newSingleMethodTransportTestServer(t, configured, other)
					assertNoDynamicMTUResponse(t, s.safeHandlePacket(query))
				})
			}
		})
	}
}

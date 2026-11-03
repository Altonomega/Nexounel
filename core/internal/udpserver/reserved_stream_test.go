package udpserver

import (
	"context"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/arq"
	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
	VpnProto "github.com/MNSH-Nexo/Nexounel/core/internal/vpnproto"
)

// dispatchTestServer builds a minimal server with one live session
// record, sufficient for processReservedStreamSyn: the session
// lookup, stream creation, and deferred finalization paths are
// exercised, but no packet ever leaves the process.
func dispatchTestServer(t *testing.T, record *sessionRecord) *Server {
	t.Helper()
	srv := &Server{
		cfg: config.ServerConfig{
			DataEncryptionMethod:          5,
			StreamResultPacketTTLSeconds:  5,
			StreamFailurePacketTTLSeconds: 5,
			ARQWindowSize:                 32,
			ARQInitialRTOSeconds:          1,
			ARQMaxRTOSeconds:              8,
			ARQControlInitialRTOSeconds:   1,
			ARQControlMaxRTOSeconds:       8,
			ARQMaxControlRetries:          3,
			ARQInactivityTimeoutSeconds:   30,
			ARQDataPacketTTLSeconds:       5,
			ARQMaxDataRetries:             3,
			ARQControlPacketTTLSeconds:    5,
		},
		sessions: newSessionStore(8, 32),
	}
	if record.Streams == nil {
		record.Streams = make(map[uint16]*Stream_server)
	}
	if record.RecentlyClosed == nil {
		record.RecentlyClosed = make(map[uint16]recentlyClosedStreamRecord)
	}
	srv.sessions.liveByID[record.ID].Store(record)
	return srv
}

func dispatchTestPacket(sessionID uint16, cookie uint8, streamID uint16, payload []byte) VpnProto.Packet {
	return VpnProto.Packet{
		PacketType:    Enums.PACKET_STREAM_SYN,
		SessionID:     sessionID,
		SessionCookie: cookie,
		StreamID:      streamID,
		SequenceNum:   1,
		Payload:       payload,
	}
}

func TestReservedDispatchServesEnrollForBootstrap(t *testing.T) {
	issuer := &fakeEnrollIssuer{}
	srv := dispatchTestServer(t, &sessionRecord{ID: 300, Cookie: 7, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	srv.SetEnrollmentIssuer(issuer)
	payload, err := enroll.MarshalTarget(enroll.EnrollmentTarget)
	if err != nil {
		t.Fatal(err)
	}
	srv.processReservedStreamSyn(context.Background(), dispatchTestPacket(300, 7, 5, payload), enroll.EnrollmentTarget)

	record, _ := srv.sessions.Get(300)
	stream, exists := record.getStream(5)
	if !exists || stream == nil {
		t.Fatal("reserved stream was not created")
	}
	stream.mu.RLock()
	connected, host, port := stream.Connected, stream.TargetHost, stream.TargetPort
	stream.mu.RUnlock()
	if !connected || host != "reserved:enroll" || port != 0 {
		t.Fatalf("stream state: connected=%v host=%q port=%d", connected, host, port)
	}
	// Release the detached handler goroutine: closing the stream
	// ARQ closes the pipe, so the handler's read fails and it
	// returns instead of waiting out the exchange deadline.
	if stream.ARQ != nil {
		stream.ARQ.Close("test done", arq.CloseOptions{Force: true})
	}
}

func TestReservedDispatchDeniesEnrollForNormal(t *testing.T) {
	srv := dispatchTestServer(t, &sessionRecord{ID: 301, Cookie: 7, NodeID: "node-1", Kind: enroll.SessionKindNormal})
	payload, err := enroll.MarshalTarget(enroll.EnrollmentTarget)
	if err != nil {
		t.Fatal(err)
	}
	srv.processReservedStreamSyn(context.Background(), dispatchTestPacket(301, 7, 5, payload), enroll.EnrollmentTarget)

	record, _ := srv.sessions.Get(301)
	stream, exists := record.getStream(5)
	if !exists || stream == nil {
		t.Fatal("stream was not created (a CONNECT_FAIL must still be queued on it)")
	}
	stream.mu.RLock()
	connected := stream.Connected
	stream.mu.RUnlock()
	if connected {
		t.Fatal("normal session must not open the enrollment target")
	}
}

func TestReservedDispatchDeniesControlForBootstrap(t *testing.T) {
	srv := dispatchTestServer(t, &sessionRecord{ID: 302, Cookie: 7, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	payload, err := enroll.MarshalTarget(enroll.ControlTarget)
	if err != nil {
		t.Fatal(err)
	}
	srv.processReservedStreamSyn(context.Background(), dispatchTestPacket(302, 7, 5, payload), enroll.ControlTarget)

	record, _ := srv.sessions.Get(302)
	stream, exists := record.getStream(5)
	if !exists || stream == nil {
		t.Fatal("stream was not created")
	}
	stream.mu.RLock()
	connected := stream.Connected
	stream.mu.RUnlock()
	if connected {
		t.Fatal("bootstrap session must not open the control target")
	}
}

func TestReservedDispatchDeniesUnknownTarget(t *testing.T) {
	srv := dispatchTestServer(t, &sessionRecord{ID: 303, Cookie: 7, NodeID: "node-1", Kind: enroll.SessionKindNormal})
	// "other" is a well-formed reserved target no handler serves.
	payload, err := enroll.MarshalTarget("other")
	if err != nil {
		t.Fatal(err)
	}
	srv.processReservedStreamSyn(context.Background(), dispatchTestPacket(303, 7, 5, payload), "other")

	record, _ := srv.sessions.Get(303)
	stream, exists := record.getStream(5)
	if !exists || stream == nil {
		t.Fatal("stream was not created")
	}
	stream.mu.RLock()
	connected := stream.Connected
	stream.mu.RUnlock()
	if connected {
		t.Fatal("unknown reserved target must fail closed, never attach")
	}
}

func TestReservedDispatchIsIdempotentReSyn(t *testing.T) {
	issuer := &fakeEnrollIssuer{}
	srv := dispatchTestServer(t, &sessionRecord{ID: 304, Cookie: 7, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
	srv.SetEnrollmentIssuer(issuer)
	payload, err := enroll.MarshalTarget(enroll.EnrollmentTarget)
	if err != nil {
		t.Fatal(err)
	}
	pkt := dispatchTestPacket(304, 7, 5, payload)
	srv.processReservedStreamSyn(context.Background(), pkt, enroll.EnrollmentTarget)
	// A retransmitted SYN for the same stream must re-announce
	// CONNECTED, never start a second handler.
	srv.processReservedStreamSyn(context.Background(), pkt, enroll.EnrollmentTarget)

	record, _ := srv.sessions.Get(304)
	stream, _ := record.getStream(5)
	stream.mu.RLock()
	connected := stream.Connected
	stream.mu.RUnlock()
	if !connected {
		t.Fatal("stream must stay connected across a re-SYN")
	}
	if stream.ARQ != nil {
		stream.ARQ.Close("test done", arq.CloseOptions{Force: true})
	}
	// Give the detached handler a moment to observe the close.
	time.Sleep(50 * time.Millisecond)
}

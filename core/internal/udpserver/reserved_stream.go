// Reserved stream dispatch: STREAM_SYN payloads that parse as a
// reserved target address (see enroll.MarshalTarget) are routed to
// an intercepted handler instead of a forward dial. The check runs
// before the forward-port resolution in processDeferredStreamSyn,
// and before the forward-disabled check: enrollment and control
// streams must not depend on forward configuration.
//
// Session-layer restriction is enforced here, fail-closed, via
// enroll.AllowedTarget: a bootstrap session opens only the
// enrollment target, a normal session opens anything except it,
// and unknown session kinds open nothing. Unknown reserved
// targets fail closed with CONNECT_FAIL: addressing is not
// authorization, and an unserved target must never hang the
// client until its deadline.
//
// Handler attachment mirrors the forward path exactly: the
// stream's ARQ is wired to one end of a net.Pipe, CONNECTED is
// announced, and the handler runs detached on the other end. The
// stream's lifetime governs the handler: when the client closes
// the stream, the pipe closes and the handler returns.
package udpserver

import (
	"context"
	"net"

	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
	VpnProto "github.com/MNSH-Nexo/Nexounel/core/internal/vpnproto"
)

// reservedTargetHost names a reserved stream in the stream's
// TargetHost field, so the already-connected re-SYN check can
// tell it apart from a forward stream (which carries ForwardIP).
func reservedTargetHost(target string) string {
	return "reserved:" + target
}

// processReservedStreamSyn routes one STREAM_SYN carrying a
// reserved target. It runs on the deferred worker, like the
// forward path, and finalizes the deferred stream on every exit.
func (s *Server) processReservedStreamSyn(ctx context.Context, vpnPacket VpnProto.Packet, target string) {
	record, ok := s.sessions.Get(vpnPacket.SessionID)
	if !ok {
		return
	}

	stream := record.getOrCreateStream(vpnPacket.StreamID, s.streamARQConfig(record.DownloadCompression), nil, s.log)
	if stream == nil || stream.ARQ == nil {
		record.enqueueOrphanReset(Enums.PACKET_STREAM_RST, vpnPacket.StreamID, 0)
		return
	}

	// Idempotent re-SYN: a stream already serving this reserved
	// target just re-announces CONNECTED (the ARQ retransmits the
	// SYN when its CONNECTED was lost). The attach below is the
	// atomic guard against starting a second handler.
	stream.mu.RLock()
	alreadyConnected := stream.Connected && stream.TargetHost == reservedTargetHost(target) && stream.TargetPort == 0
	stream.mu.RUnlock()
	if alreadyConnected {
		stream.ARQ.SendControlPacketWithTTL(
			Enums.PACKET_STREAM_CONNECTED,
			vpnPacket.SequenceNum,
			0,
			0,
			nil,
			Enums.DefaultPacketPriority(Enums.PACKET_STREAM_CONNECTED),
			true,
			nil,
			s.cfg.StreamResultPacketTTL(),
		)
		s.finalizeDeferredConnectStream(vpnPacket.SessionID, vpnPacket.StreamID, "reserved", "already-connected")
		return
	}

	failClosed := func(reason string) {
		stream.ARQ.SendControlPacketWithTTL(
			Enums.PACKET_STREAM_CONNECT_FAIL,
			vpnPacket.SequenceNum,
			0,
			0,
			nil,
			Enums.DefaultPacketPriority(Enums.PACKET_STREAM_CONNECT_FAIL),
			true,
			nil,
			s.cfg.StreamFailurePacketTTL(),
		)
		s.finalizeDeferredConnectStream(vpnPacket.SessionID, vpnPacket.StreamID, "reserved", reason)
	}

	// Session-layer restriction, fail-closed.
	if !enroll.AllowedTarget(record.Kind, target) {
		if s.log != nil {
			s.log.Warnf("reserved target %q denied for session %d (kind %d, node %q)", target, vpnPacket.SessionID, record.Kind, record.NodeID)
		}
		failClosed("reserved-target-denied")
		return
	}

	// Only served targets reach the attach. An unserved target
	// fails closed here, before any stream state is created for
	// it beyond the pending stream itself.
	switch target {
	case enroll.EnrollmentTarget, enroll.ControlTarget:
		// Served below.
	default:
		if s.log != nil {
			s.log.Warnf("unknown reserved target %q from session %d", target, vpnPacket.SessionID)
		}
		failClosed("reserved-target-unknown")
		return
	}

	serverEnd, handlerEnd := net.Pipe()
	if record.isClosed() || !stream.attachUpstreamConn(serverEnd, reservedTargetHost(target), 0, "CONNECTED") {
		_ = serverEnd.Close()
		_ = handlerEnd.Close()
		s.finalizeDeferredConnectStream(vpnPacket.SessionID, vpnPacket.StreamID, "reserved", "attach-rejected")
		return
	}
	if !s.shouldExecuteDeferredPacket(vpnPacket) {
		_ = serverEnd.Close()
		_ = handlerEnd.Close()
		s.finalizeDeferredConnectStream(vpnPacket.SessionID, vpnPacket.StreamID, "reserved", "stale-after-attach")
		return
	}

	stream.ARQ.SetLocalConn(serverEnd)
	stream.ARQ.SendControlPacketWithTTL(
		Enums.PACKET_STREAM_CONNECTED,
		vpnPacket.SequenceNum,
		0,
		0,
		nil,
		Enums.DefaultPacketPriority(Enums.PACKET_STREAM_CONNECTED),
		true,
		nil,
		s.cfg.StreamResultPacketTTL(),
	)
	stream.ARQ.SetIOReady(true)
	s.finalizeDeferredConnectStream(vpnPacket.SessionID, vpnPacket.StreamID, "reserved", "connected")

	// Detached: the stream's lifetime governs the handler through
	// the pipe. The handler never touches server stream state.
	switch target {
	case enroll.EnrollmentTarget:
		go s.serveEnrollmentStream(handlerEnd, record)
	case enroll.ControlTarget:
		go s.serveControlStream(handlerEnd, record)
	}
}

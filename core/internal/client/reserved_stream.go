// Reserved stream opener: the client side of an addressed stream
// (enrollment, control) inside the node's own DNS session.
//
// A reserved stream is a normal ARQ stream whose STREAM_SYN
// payload carries a reserved target address (see
// enroll.MarshalTarget) instead of a forward port. The server
// intercepts it instead of dialing. The stream is opened on the
// current session — the session key is the authentication — and
// the caller gets a net.Conn speaking the handler's framed
// protocol. Closing the conn ends the stream, exactly as closing
// a forwarded TCP connection does.
//
// Fail-closed: anything but an explicit STREAM_CONNECTED within
// the context deadline (no session, no stream ID, server refusal,
// timeout) tears the stream down and returns an error. No partial
// stream is ever handed out.
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/arq"
	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
)

var (
	// ErrNoReservedSession is returned when a reserved stream is
	// requested without a ready session.
	ErrNoReservedSession = errors.New("no ready session for a reserved stream")
	// ErrReservedStreamRefused is returned when the server refuses
	// the reserved target (denied for this session kind, unknown
	// target, or the stream closed before connecting).
	ErrReservedStreamRefused = errors.New("reserved stream refused")
)

// reservedStreamWaitPoll is the interval at which the opener
// polls the stream status while waiting for STREAM_CONNECTED.
const reservedStreamWaitPoll = 10 * time.Millisecond

// OpenReservedStream opens a stream to target on the current
// session and returns a conn speaking the handler's protocol.
// The caller owns the conn: Close ends the stream. The context
// bounds the wait for STREAM_CONNECTED only; the returned conn
// is independent of it afterwards.
func (c *Client) OpenReservedStream(ctx context.Context, target string) (net.Conn, error) {
	payload, err := enroll.MarshalTarget(target)
	if err != nil {
		return nil, fmt.Errorf("reserved target %q: %w", target, err)
	}
	if c == nil || !c.SessionReady() || c.sessionID == 0 {
		return nil, ErrNoReservedSession
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	streamID, ok := c.get_new_stream_id()
	if !ok {
		return nil, errors.New("no stream ID available for a reserved stream")
	}
	localEnd, remoteEnd := net.Pipe()
	s := c.new_stream(streamID, localEnd, nil)
	if s == nil {
		_ = localEnd.Close()
		_ = remoteEnd.Close()
		return nil, errors.New("could not create a reserved stream")
	}
	arqObj, ok := s.Stream.(*arq.ARQ)
	if !ok || arqObj == nil {
		c.removeStream(streamID)
		_ = localEnd.Close()
		_ = remoteEnd.Close()
		return nil, errors.New("reserved stream has no ARQ engine")
	}

	cleanup := func() {
		c.removeStream(streamID)
		_ = localEnd.Close()
		_ = remoteEnd.Close()
	}

	arqObj.SendControlPacketWithTTL(
		Enums.PACKET_STREAM_SYN,
		0,
		0,
		0,
		payload,
		Enums.DefaultPacketPriority(Enums.PACKET_STREAM_SYN),
		true,
		nil,
		120*time.Second,
	)

	// Wait for STREAM_CONNECTED (status active). Any terminal
	// status, a closed ARQ, or context expiry fails closed.
	ticker := time.NewTicker(reservedStreamWaitPoll)
	defer ticker.Stop()
	for {
		switch s.StatusValue() {
		case streamStatusActive:
			return remoteEnd, nil
		case streamStatusCancelled, streamStatusDraining, streamStatusClosing, streamStatusTimeWait, streamStatusClosed:
			cleanup()
			return nil, ErrReservedStreamRefused
		}
		if arqObj.IsClosed() {
			cleanup()
			return nil, ErrReservedStreamRefused
		}
		select {
		case <-ctx.Done():
			cleanup()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

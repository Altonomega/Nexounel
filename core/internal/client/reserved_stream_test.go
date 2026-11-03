package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
)

func TestOpenReservedStreamRejectsBadTarget(t *testing.T) {
	c := createTestClient(t)
	for _, target := range []string{"", "ENROLL", "enroll-me"} {
		if _, err := c.OpenReservedStream(context.Background(), target); err == nil {
			t.Errorf("target %q must be refused before any session state is touched", target)
		}
	}
}

func TestOpenReservedStreamRequiresSession(t *testing.T) {
	c := createTestClient(t)
	// Fresh test client: no session established.
	if _, err := c.OpenReservedStream(context.Background(), enroll.EnrollmentTarget); !errors.Is(err, ErrNoReservedSession) {
		t.Fatalf("err = %v, want ErrNoReservedSession", err)
	}
	c.sessionReady = true
	// Ready flag without an assigned session ID is still no session.
	if _, err := c.OpenReservedStream(context.Background(), enroll.EnrollmentTarget); !errors.Is(err, ErrNoReservedSession) {
		t.Fatalf("err = %v, want ErrNoReservedSession", err)
	}
}

func TestOpenReservedStreamFailsClosedOnTimeout(t *testing.T) {
	c := createTestClient(t)
	c.sessionReady = true
	c.sessionID = 300
	// No server answers: the wait must expire with the context and
	// the stream must be torn down, never handed out.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	conn, err := c.OpenReservedStream(ctx, enroll.EnrollmentTarget)
	if err == nil {
		_ = conn.Close()
		t.Fatal("must fail when no server answers")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("wait took %s, far past the deadline", elapsed)
	}
	c.streamsMu.Lock()
	remaining := len(c.active_streams)
	c.streamsMu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d streams left behind after a failed open", remaining)
	}
}

func TestOpenReservedStreamHonorsCancellation(t *testing.T) {
	c := createTestClient(t)
	c.sessionReady = true
	c.sessionID = 300
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.OpenReservedStream(ctx, enroll.EnrollmentTarget); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

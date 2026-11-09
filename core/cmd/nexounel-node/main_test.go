package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

// freeBasePort allocates a free loopback port and returns it, leaving room
// for a 10-port forward range above it (base..base+9).
func freeBasePort(t *testing.T) int {
	t.Helper()
	for {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("allocating test port: %v", err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		if port <= 65525 {
			return port
		}
	}
}

// setBindBackoff shrinks the bind-retry budget for the test and restores it
// afterwards.
func setBindBackoff(t *testing.T, d []time.Duration) {
	t.Helper()
	orig := forwardListenerBindBackoff
	forwardListenerBindBackoff = d
	t.Cleanup(func() { forwardListenerBindBackoff = orig })
}

type listenResult struct {
	listeners []net.Listener
	err       error
}

func closeListeners(ls []net.Listener) {
	for _, l := range ls {
		_ = l.Close()
	}
}

// TestCoordinatorListenTransientHolder is the §14 race reproduced in the
// sandbox: a holder grabs one port of the forward range, releases it
// mid-retry, and listen must succeed with all 10 listeners. Fails on the
// old fail-fast code (EADDRINUSE returned immediately).
func TestCoordinatorListenTransientHolder(t *testing.T) {
	setBindBackoff(t, []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond})
	base := freeBasePort(t)
	held := base + 5

	holder, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", held))
	if err != nil {
		t.Fatalf("holding test port %d: %v", held, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord := &coordinator{}
	resCh := make(chan listenResult, 1)
	go func() {
		ls, err := coord.listen(ctx, "127.0.0.1", base, base+9)
		resCh <- listenResult{ls, err}
	}()

	// Release the holder mid-retry (after the first retry at ~100 ms,
	// before the last retry at ~1.5 s).
	time.Sleep(250 * time.Millisecond)
	_ = holder.Close()

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("listen with transient holder: unexpected error: %v", res.err)
		}
		defer closeListeners(res.listeners)
		if len(res.listeners) != 10 {
			t.Fatalf("listener count: got %d, want 10", len(res.listeners))
		}
		// The formerly-held port must actually be listening now.
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", held), 2*time.Second)
		if err != nil {
			t.Fatalf("dial formerly-held port %d: %v", held, err)
		}
		_ = conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("listen did not return within 5 s")
	}
}

// TestCoordinatorListenPermanentHolder proves the fail-fast behaviour is
// preserved: a holder that never releases still fails after the budget, and
// the already-bound listeners are closed (no leak).
func TestCoordinatorListenPermanentHolder(t *testing.T) {
	setBindBackoff(t, []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond})
	base := freeBasePort(t)
	held := base + 5

	holder, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", held))
	if err != nil {
		t.Fatalf("holding test port %d: %v", held, err)
	}
	defer func() { _ = holder.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord := &coordinator{}

	start := time.Now()
	ls, err := coord.listen(ctx, "127.0.0.1", base, base+9)
	elapsed := time.Since(start)
	if err == nil {
		defer closeListeners(ls)
		t.Fatal("listen with permanent holder: expected error, got nil")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("error should wrap EADDRINUSE, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("permanent holder: listen took %v, budget should bound it", elapsed)
	}

	// Already-bound listeners (base..base+4) must be closed: dialling them
	// must fail with connection refused.
	for port := base; port < held; port++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("port %d still listening after failed listen (listener leak)", port)
		}
	}
	// The holder itself must still be listening (we closed only our own).
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", held), 2*time.Second)
	if err != nil {
		t.Fatalf("holder port %d should still be listening: %v", held, err)
	}
	_ = conn.Close()
}

// TestCoordinatorListenCleanPath is the common case: no holder, first attempt
// succeeds with zero retry delay.
func TestCoordinatorListenCleanPath(t *testing.T) {
	setBindBackoff(t, []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond})
	base := freeBasePort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	coord := &coordinator{}

	start := time.Now()
	ls, err := coord.listen(ctx, "127.0.0.1", base, base+9)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("clean listen: unexpected error: %v", err)
	}
	defer closeListeners(ls)
	if len(ls) != 10 {
		t.Fatalf("listener count: got %d, want 10", len(ls))
	}
	if elapsed > time.Second {
		t.Fatalf("clean listen took %v, expected zero retry delay", elapsed)
	}
}

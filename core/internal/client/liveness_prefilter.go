// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// liveness_prefilter.go — scale-audit fix F1b: cheap liveness pre-filter.
//
// A dead resolver is the most expensive thing the MTU scan can meet: the
// binary search pays the full per-query timeout times the retry budget at
// EVERY step (high check, low check, then reject), so a fleet that is
// mostly dead costs hours per restart at the default parallelism. The
// pre-filter spends one small probe (retried once) per connection and
// keeps dead resolvers out of the binary-search pass entirely.
//
// Safety: the probe reuses sendUploadMTUProbe verbatim at the smallest
// testable size, so a resolver that answers it is exactly a resolver the
// binary search's low check would accept on its first attempt. The only
// behavioral delta is the lossy corner: a resolver whose replies are lost
// on BOTH attempts is filtered even though the full search (up to
// mtuTestRetries attempts per candidate) might have accepted it. That
// corner needs sustained high loss; healthy resolvers are unaffected.
// The filter is gated to large fleets so small fleets keep byte-identical
// behavior (no extra queries, no filtering).
// ==============================================================================

package client

import (
	"context"
	"sync"

	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
)

const (
	// livenessPrefilterMinFleet gates the pre-filter: fleets at or below
	// this size run the full probe unchanged.
	livenessPrefilterMinFleet = 256
	// livenessPrefilterWorkers bounds concurrent single-query probes. The
	// probes are timeout-bound, not CPU-bound, so this is deliberately far
	// above the MTU scan parallelism: with all-dead resolvers the wall
	// clock is ~attempts*timeout/workers per fleet, not per resolver.
	livenessPrefilterWorkers = 512
	// livenessPrefilterAttempts bounds the probes per connection: one small
	// probe, retried once to rescue single-packet loss.
	livenessPrefilterAttempts = 2
)

// livenessPrefilterEnabled reports whether the pre-filter runs for a fleet
// of n connections.
func livenessPrefilterEnabled(n int) bool {
	return n > livenessPrefilterMinFleet
}

// probeConnectionLiveness sends up to livenessPrefilterAttempts minimal
// upload probes at the smallest testable size and reports whether any
// answered. It opens one transport per connection, like probeConnectionMTU,
// and reuses the probe machinery verbatim — only the binary search is
// skipped. Probes are quiet: per-resolver logging at this scale would bury
// the scan output.
func (c *Client) probeConnectionLiveness(ctx context.Context, conn *Connection) bool {
	transport, err := c.newQueryTransport(conn.ResolverLabel)
	if err != nil {
		return false
	}
	defer func() { _ = transport.Close() }()

	size := max(c.cfg.MinUploadMTU, defaultMTUMinFloor)
	qType := uint16(Enums.DNS_RECORD_TYPE_TXT)
	if qTypes := c.mtuProbeQueryTypes(false); len(qTypes) > 0 {
		qType = qTypes[0]
	}
	for attempt := 0; attempt < livenessPrefilterAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return false
		}
		ok, _, err := c.sendUploadMTUProbe(ctx, conn, transport, size, mtuProbeOptions{
			IsRetry:   attempt > 0,
			Quiet:     true,
			QueryType: qType,
		})
		if err == nil && ok {
			return true
		}
	}
	return false
}

// prefilterLiveConnections returns the subset of indices whose resolver
// answered the liveness probe, preserving input order. When the fleet is
// at or below the gate, when ctx is already done, or when ctx is cancelled
// mid-run, it returns indices unchanged: the full probe then runs (and
// applies the cancellation itself), so filtering can never strand a fleet.
func (c *Client) prefilterLiveConnections(ctx context.Context, indices []int) []int {
	if c == nil {
		return indices
	}
	return c.prefilterLiveConnectionsWithProber(ctx, indices, c.probeConnectionLiveness)
}

// prefilterLiveConnectionsWithProber is prefilterLiveConnections with an
// injectable prober, so the pool mechanics are testable without a network.
func (c *Client) prefilterLiveConnectionsWithProber(ctx context.Context, indices []int, prober func(context.Context, *Connection) bool) []int {
	if !livenessPrefilterEnabled(len(indices)) || prober == nil {
		return indices
	}
	if err := ctx.Err(); err != nil {
		return indices
	}
	if len(c.connections) == 0 {
		return indices
	}

	live := make([]bool, len(c.connections))
	workers := min(livenessPrefilterWorkers, len(indices))
	jobs := make(chan int, len(indices))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				if idx < 0 || idx >= len(c.connections) {
					continue
				}
				if prober(ctx, &c.connections[idx]) {
					live[idx] = true
				}
			}
		}()
	}
	cancelled := false
	for _, idx := range indices {
		select {
		case <-ctx.Done():
			cancelled = true
		case jobs <- idx:
		}
		if cancelled {
			break
		}
	}
	close(jobs)
	wg.Wait()
	if cancelled {
		return indices
	}

	out := make([]int, 0, len(indices))
	for _, idx := range indices {
		if idx >= 0 && idx < len(live) && live[idx] {
			out = append(out, idx)
		}
	}
	return out
}

// livenessSkipSet probes fleet liveness once and returns the set of
// connection indices to skip in the binary-search pass, or nil when the
// pre-filter is gated off or every resolver answered. It is computed fresh
// per scan call so transport fallback re-evaluates liveness on the new
// transport instead of trusting a verdict from the failed one.
func (c *Client) livenessSkipSet(ctx context.Context) map[int]bool {
	total := len(c.connections)
	if !livenessPrefilterEnabled(total) {
		return nil
	}
	indices := make([]int, total)
	for i := range indices {
		indices[i] = i
	}
	live := c.prefilterLiveConnections(ctx, indices)
	if len(live) == total {
		return nil
	}
	liveSet := make(map[int]bool, len(live))
	for _, idx := range live {
		liveSet[idx] = true
	}
	skip := make(map[int]bool, total-len(live))
	for _, idx := range indices {
		if !liveSet[idx] {
			skip[idx] = true
		}
	}
	if c.log != nil && c.mtuInfoEnabled() {
		c.log.Infof(
			"<cyan>[Liveness]</cyan> pre-filter: <green>%d</green> live, <yellow>%d</yellow> dead skipped (fleet <cyan>%d</cyan>)",
			len(live), len(skip), total,
		)
	}
	return skip
}

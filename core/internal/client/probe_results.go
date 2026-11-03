package client

import (
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
)

// ProbeResults snapshots the per-resolver measurements from the most
// recent MTU probe pass, adapted to multisession.ProbeResult for the
// multi-session coordinator.
//
// Connections are domain x resolver rows; this accessor deduplicates by
// resolver address (IP:port), keeping the row with the largest download
// capacity (upload breaks ties), because capacity clustering is a
// per-resolver property and the coordinator rebuilds resolver lists from
// ResolverAddress entries. Rows for resolvers that failed probing are
// reported with Valid=false and zero capacities so the clusterer can
// place them in the reserves instead of dropping them silently.
//
// The snapshot is taken under the same lock order as the other snapshot
// readers (mtuStateMu, then balancer.mu). RTT is read afterwards through
// the balancer's own accessor and is advisory.
func (c *Client) ProbeResults() []multisession.ProbeResult {
	if c == nil {
		return nil
	}
	c.mtuStateMu.Lock()
	if c.balancer != nil {
		c.balancer.mu.Lock()
	}
	conns := make([]Connection, len(c.connections))
	copy(conns, c.connections)
	if c.balancer != nil {
		c.balancer.mu.Unlock()
	}
	c.mtuStateMu.Unlock()

	best := make(map[string]multisession.ProbeResult)
	order := make([]string, 0, len(conns))
	for _, conn := range conns {
		key := conn.Resolver
		loss := conn.UploadMTULoss
		if conn.DownloadMTULoss > loss {
			loss = conn.DownloadMTULoss
		}
		result := multisession.ProbeResult{
			Resolver:    conn.Resolver,
			Port:        conn.ResolverPort,
			UploadMTU:   conn.UploadMTUBytes,
			DownloadMTU: conn.DownloadMTUBytes,
			Loss:        loss,
			Valid:       conn.IsValid,
		}
		if prev, ok := best[key]; !ok {
			best[key] = result
			order = append(order, key)
		} else if result.DownloadMTU > prev.DownloadMTU ||
			(result.DownloadMTU == prev.DownloadMTU && result.UploadMTU > prev.UploadMTU) {
			best[key] = result
		}
	}

	results := make([]multisession.ProbeResult, 0, len(best))
	for _, key := range order {
		result := best[key]
		if c.balancer != nil {
			if rtt, ok := c.balancer.AverageRTT(connKeyForProbe(conns, key)); ok {
				result.RTT = rtt
			}
		}
		results = append(results, result)
	}
	return results
}

// SyncedMTUs returns the operating point the session synced to (the
// MTUs the probe pass settled on), or 0,0 before the probe pass
// completes. The mesh heartbeat reports these for single-session
// nodes; multi-session nodes report per-class operating points
// instead. It reads the atomic status mirrors the probe path
// maintains, so it is race-free without locking the probe state.
func (c *Client) SyncedMTUs() (upload, download int) {
	if c == nil {
		return 0, 0
	}
	return int(c.statusUploadMTU.Load()), int(c.statusDownloadMTU.Load())
}

// ActiveStreamCount returns the number of live local streams
// (forwarded connections) on this client. Read-only snapshot for
// the mesh heartbeat.
func (c *Client) ActiveStreamCount() int {
	if c == nil {
		return 0
	}
	c.streamsMu.RLock()
	defer c.streamsMu.RUnlock()
	return len(c.active_streams)
}

// connKeyForProbe finds the balancer key of the first connection row for a
// resolver address. Balancer stats are keyed by connection Key, not by
// resolver address.
func connKeyForProbe(conns []Connection, resolver string) string {
	for _, conn := range conns {
		if conn.Resolver == resolver {
			return conn.Key
		}
	}
	return resolver
}

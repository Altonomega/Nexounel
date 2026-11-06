// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// preknown_verify.go — scale-audit fix F1a: cheap verification of cached
// MTUs.
//
// LOG_BASED_MTU_VERIFY=true (the default) used to mean "run the full binary
// search anyway", which made the resolver-cache fast start dead code in
// practice: BootstrapFromLogs pre-filled MTUs that the full scan then wiped.
// Verification closes that gap: a cached resolver is re-checked with ONE
// probe per direction at the cached sizes — no binary search — and only
// resolvers that fail verification pay for a full re-probe.
//
// A failed verification never rejects a resolver outright: the connection
// is reset and fully re-probed, so a resolver whose capacity shrank (or a
// probe lost to transient loss) is re-measured rather than dropped.
// ==============================================================================

package client

import (
	"context"
	"sync"

	Enums "github.com/Altonomega/Nexounel/core/internal/enums"
)

const (
	// preknownVerifyMinParallelism floors the verification worker count.
	// Verification probes are single cheap queries, so the floor is far
	// above the logs-mode scan parallelism (32); an operator-tuned higher
	// MTU_TEST_PARALLELISM is still honored (see verifyPreknownMTUs).
	preknownVerifyMinParallelism = 128
)

// preknownMTUIndices returns the indices of connections that carry a cached
// MTU (valid with a measured download MTU): the exact complement of
// connectionsWithoutPreknownMTU.
func preknownMTUIndices(conns []Connection) []int {
	out := make([]int, 0, len(conns))
	for i := range conns {
		if conns[i].IsValid && conns[i].DownloadMTUBytes > 0 {
			out = append(out, i)
		}
	}
	return out
}

// verifyPreknownMTUs re-checks cached MTUs with one probe per direction at
// the cached sizes and returns the indices that failed verification. Failed
// connections have their scan state reset, ready for a full probe. Passing
// connections keep their cached values untouched.
//
// The upload probe runs first and short-circuits: a resolver that cannot
// carry the cached upload size is failed without spending the download
// probe. Probes are quiet and single-attempt — the full re-probe is the
// retry. A cancelled context fails every unverified index; the caller's
// full probe applies the cancellation itself.
func (c *Client) verifyPreknownMTUs(ctx context.Context, indices []int) []int {
	if len(indices) == 0 {
		return nil
	}
	passed := make([]bool, len(c.connections))
	workers := min(max(c.cfg.MTUTestParallelism, preknownVerifyMinParallelism), len(indices))
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
				if c.verifyOnePreknownMTU(ctx, &c.connections[idx]) {
					passed[idx] = true
				}
			}
		}()
	}
	for _, idx := range indices {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			goto collect
		case jobs <- idx:
		}
	}
	close(jobs)
	wg.Wait()

collect:
	failed := make([]int, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(passed) || !passed[idx] {
			failed = append(failed, idx)
		}
	}
	for _, idx := range failed {
		c.prepareConnectionMTUScanState(&c.connections[idx])
	}
	return failed
}

// verifyOnePreknownMTU probes one cached connection at its cached sizes.
// Both directions must answer; either failure fails the connection.
func (c *Client) verifyOnePreknownMTU(ctx context.Context, conn *Connection) bool {
	transport, err := c.newQueryTransport(conn.ResolverLabel)
	if err != nil {
		return false
	}
	defer func() { _ = transport.Close() }()

	upType := uint16(Enums.DNS_RECORD_TYPE_TXT)
	if qTypes := c.mtuProbeQueryTypes(false); len(qTypes) > 0 {
		upType = qTypes[0]
	}
	ok, _, err := c.sendUploadMTUProbe(ctx, conn, transport, conn.UploadMTUBytes, mtuProbeOptions{
		Quiet:     true,
		QueryType: upType,
	})
	if err != nil || !ok {
		return false
	}

	downType := uint16(Enums.DNS_RECORD_TYPE_TXT)
	if qTypes := c.mtuProbeQueryTypes(true); len(qTypes) > 0 {
		downType = qTypes[0]
	}
	ok, _, err = c.sendDownloadMTUProbe(ctx, conn, transport, conn.DownloadMTUBytes, conn.UploadMTUBytes, mtuProbeOptions{
		Quiet:     true,
		QueryType: downType,
	})
	return err == nil && ok
}

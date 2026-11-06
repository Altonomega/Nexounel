// Package tunnelinfo describes the tunnel mode to terminal users.
// It contains presentation only; it never changes configuration or credentials.
package tunnelinfo

import (
	"fmt"
	"strings"

	"github.com/Altonomega/Nexounel/core/internal/config"
)

// ModeLabel returns the display name for the tunnel mode.
func ModeLabel(mode string) string {
	if mode == config.TunnelLegacy {
		return "Nexounel normal"
	}
	return "Nexounel"
}

// Client returns setup and fallback guidance without exposing credentials.
func Client(cfg config.ClientConfig) []string {
	lines := []string{
		"Mode: " + ModeLabel(cfg.TunnelMode) + " | resolver transport: " + cfg.ResolverTransport,
		"Normal mode uses the configured delegated domains and ENCRYPTION_KEY.",
		fmt.Sprintf("Options: discovery %s; cache %s; padding %s; label jitter %s.", onOff(cfg.ResolverDiscoveryEnabled), onOff(strings.TrimSpace(cfg.ResolverDiscoveryCacheFile) != ""), padding(cfg.DNSPaddingBlockSize), onOff(cfg.QNameLabelJitter)),
		"Optional settings: RESOLVER_DISCOVERY_*, DNS_PADDING_BLOCK_SIZE (encrypted modes only), QNAME_LABEL_COUNT_JITTER.",
		"DOMAINS + STANDBY_DOMAINS allow up to 8 delegated domains. Failover applies to new connections; existing streams are not migrated.",
		"Keep defaults initially. Use hard QUERY_RATE_LIMIT_* budgets when the resolver fleet needs a strict query ceiling.",
	}
	return lines
}

// Server describes the server setup. Runtime startup logs remain the
// authority for domain-specific eligibility and listener readiness.
func Server(cfg config.ServerConfig) []string {
	lines := []string{
		"Modes: Nexounel normal mode on the same DNS listener.",
		"Clients use TUNNEL_MODE=legacy. The server TUNNEL_MODE setting does not disable normal clients.",
		fmt.Sprintf("Capacity ceilings: %d sessions; %d streams/session. Session counts are not guaranteed user capacity.", cfg.MaxActiveSessions, cfg.MaxStreamsPerSession),
	}
	return append(lines,
		"Check startup logs for skipped long domains; normal mode remains available on those domains.",
		"HTTP3/DoQ are client-to-resolver options and do not create authoritative listeners. Existing server DoT/DoH listeners are configured separately.",
	)
}

func onOff(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}
func padding(size int) string {
	if size == 0 {
		return "off"
	}
	return fmt.Sprintf("%d bytes", size)
}

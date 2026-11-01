package config

import (
	"fmt"
	"strings"
)

const TunnelLegacy = "legacy"

func normalizeTunnelMode(mode string) (string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = TunnelLegacy
	}
	if mode != TunnelLegacy {
		return "", fmt.Errorf("invalid TUNNEL_MODE %q (want legacy)", mode)
	}
	return mode, nil
}

func validateResolverOptions(c ClientConfig) error {
	if c.DNSPaddingBlockSize != 0 {
		if c.DNSPaddingBlockSize < 16 || c.DNSPaddingBlockSize > 4096 {
			return fmt.Errorf("DNS_PADDING_BLOCK_SIZE must be 0 (off) or 16..4096")
		}
		if c.ResolverTransport != "dot" && c.ResolverTransport != "doh" && c.ResolverTransport != "doh3" && c.ResolverTransport != "doq" {
			return fmt.Errorf("DNS_PADDING_BLOCK_SIZE requires an encrypted resolver transport")
		}
	}
	if c.ResolverDiscoveryWant < 1 || c.ResolverDiscoveryWant > 4096 || c.ResolverDiscoveryConcurrency < 1 || c.ResolverDiscoveryConcurrency > 64 || c.ResolverDiscoveryPaceMilliseconds < 1 || c.ResolverDiscoveryPaceMilliseconds > 60000 {
		return fmt.Errorf("discovery WANT must be 1..4096, CONCURRENCY 1..64 and PACE_MILLISECONDS 1..60000")
	}
	if len(c.ResolverDiscoveryCandidates) > 256 {
		return fmt.Errorf("RESOLVER_DISCOVERY_CANDIDATES is limited to 256 endpoints")
	}
	if len(c.ResolverDiscoveryNetworkID) > 256 {
		return fmt.Errorf("RESOLVER_DISCOVERY_NETWORK_ID is limited to 256 characters")
	}
	return nil
}

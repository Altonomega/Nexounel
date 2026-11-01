package config

// optionHelp supplements generated flag names with the constraints users need
// before choosing a tunnel mode. It does not change parsing or defaults.
func optionHelp(key string, server bool) string {
	if server {
		switch key {
		case "TUNNEL_MODE":
			return "Compatibility setting: legacy is the only tunnel mode"
		}
		return ""
	}
	switch key {
	case "RESOLVER_DISCOVERY_WANT":
		return "Desired distinct healthy Max discovery resolvers, 1..4096; checks remain bounded and paced"
	case "TUNNEL_MODE":
		return "legacy (normal mode, the only mode)"
	case "RESOLVER_TRANSPORT":
		return "auto, udp, tcp, dot, doh, doh3 (HTTP/3), doq; encrypted modes require a compatible resolver"
	case "RESOLVER_DISCOVERY_ENABLED":
		return "Opt-in authenticated resolver discovery; default off"
	case "RESOLVER_DISCOVERY_CACHE_FILE":
		return "Optional resolver hint cache; re-authenticates candidates; separate network labels with RESOLVER_DISCOVERY_NETWORK_ID"
	case "DNS_PADDING_BLOCK_SIZE":
		return "Opt-in EDNS query padding: 0 off, 16..4096 bytes with encrypted resolver transport only"
	case "QNAME_LABEL_COUNT_JITTER":
		return "Opt-in label-count shaping; default off"
	}
	return ""
}

package client

import "github.com/Altonomega/Nexounel/core/internal/tunnelinfo"

// TunnelGuidance reports the configured mode and setup requirements without
// exposing the key, proxy password, resolver pin or other credentials.
func (c *Client) TunnelGuidance() []string {
	if c == nil {
		return nil
	}
	return tunnelinfo.Client(c.cfg)
}

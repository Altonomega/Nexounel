package udpserver

import (
	DnsParser "github.com/Altonomega/Nexounel/core/internal/dnsparser"
	"github.com/Altonomega/Nexounel/core/internal/security"
	VpnProto "github.com/Altonomega/Nexounel/core/internal/vpnproto"
)

func (s *Server) buildTunnelResponse(question []byte, name, domain string, packet VpnProto.Packet, mode uint8, codec *security.Codec) ([]byte, error) {
	base64, valid := parseMTUProbeBaseEncoding(mode)
	if !valid {
		return nil, security.ErrInvalidCiphertext
	}
	if mode&security.DownstreamEncryptedFlag != 0 {
		if packet.LegacySessionID || codec == nil || codec.Method() == 0 {
			return nil, security.ErrInvalidCiphertext
		}
		return DnsParser.BuildEncryptedVPNResponsePacketMatchingQuery(question, name, domain, packet, base64, s.cfg.ARecordDataDelivery, s.cfg.AAAARecordDataDelivery, codec)
	}
	return DnsParser.BuildVPNResponsePacketMatchingQuery(question, name, domain, packet, base64, s.cfg.ARecordDataDelivery, s.cfg.AAAARecordDataDelivery)
}

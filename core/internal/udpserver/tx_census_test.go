// ==============================================================================
// Nexounel — derived from the CottenDNS core (MIT; see NOTICE).
// ==============================================================================
// Queue-census tests (server side): identical ACK/NACK frames pushed
// twice while the first is still queued must collapse to one queued
// frame. This is the pre-existing MLQ census behavior the ARQ
// experiment relies on (docs/ARQ-PROTOTYPE.md, finding F-C1); the
// test pins it on the server enqueue path, mirroring the client test
// in internal/client/tx_census_test.go.
// ==============================================================================

package udpserver

import (
	"testing"

	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
	"github.com/MNSH-Nexo/Nexounel/core/internal/mlq"
)

func TestServerPushTXPacketDedupsIdenticalAckNack(t *testing.T) {
	stream := &Stream_server{
		ID:      7,
		TXQueue: mlq.New[*serverStreamTXPacket](8),
	}

	for _, packetType := range []uint8{Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_DATA_NACK} {
		first := stream.PushTXPacket(1, packetType, 42, 0, 0, 0, 0, nil)
		if !first {
			t.Fatalf("first %s push: got false, want true", Enums.PacketTypeName(packetType))
		}
		second := stream.PushTXPacket(1, packetType, 42, 0, 0, 0, 0, nil)
		if second {
			t.Fatalf("second identical %s push: got true, want false (census dedup)", Enums.PacketTypeName(packetType))
		}
		if got := stream.TXQueue.FastSize(); got != 1 {
			t.Fatalf("queue size after duplicate %s: got=%d want=1", Enums.PacketTypeName(packetType), got)
		}
		// A different sequence number is a different frame and queues.
		third := stream.PushTXPacket(1, packetType, 43, 0, 0, 0, 0, nil)
		if !third {
			t.Fatalf("distinct %s SN 43: got false, want true", Enums.PacketTypeName(packetType))
		}
		// Drain before the next iteration so sizes stay exact.
		for stream.TXQueue.FastSize() > 0 {
			_, _, ok := stream.TXQueue.Pop(func(p *serverStreamTXPacket) uint64 {
				return Enums.PacketIdentityKey(stream.ID, p.PacketType, p.SequenceNum, p.FragmentID)
			})
			if !ok {
				break
			}
		}
	}
}

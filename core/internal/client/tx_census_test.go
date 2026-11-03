// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Queue-census tests: identical ACK/NACK frames pushed twice while the
// first is still queued must collapse to one queued frame. This is the
// pre-existing MLQ census behavior the ARQ experiment relies on
// (docs/ARQ-PROTOTYPE.md, finding F-C1); these tests pin it so the
// experiment's query savings cannot silently regress into duplicate
// queue entries. The remaining per-frame multiplication is the
// send-side duplication count, pinned by the experiment in
// runtimePacketDuplicationCount — not the queue.
// ==============================================================================

package client

import (
	"testing"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	Enums "github.com/MNSH-Nexo/Nexounel/core/internal/enums"
	"github.com/MNSH-Nexo/Nexounel/core/internal/mlq"
)

func TestPushTXPacketDedupsIdenticalAckNack(t *testing.T) {
	c := buildTestClientWithResolvers(config.ClientConfig{}, "a", "b")
	stream := &Stream_client{
		client:   c,
		StreamID: 7,
		txQueue:  mlq.New[*clientStreamTXPacket](8),
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
		if got := stream.txQueue.FastSize(); got != 1 {
			t.Fatalf("queue size after duplicate %s: got=%d want=1", Enums.PacketTypeName(packetType), got)
		}
		// A different sequence number is a different frame and queues.
		third := stream.PushTXPacket(1, packetType, 43, 0, 0, 0, 0, nil)
		if !third {
			t.Fatalf("distinct %s SN 43: got false, want true", Enums.PacketTypeName(packetType))
		}
		// Drain this packet type before the next iteration so sizes stay exact.
		for stream.txQueue.FastSize() > 0 {
			_, _, ok := stream.txQueue.Pop(func(p *clientStreamTXPacket) uint64 {
				return Enums.PacketIdentityKey(stream.StreamID, p.PacketType, p.SequenceNum, p.FragmentID)
			})
			if !ok {
				break
			}
		}
	}
}

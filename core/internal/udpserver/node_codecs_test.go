package udpserver

import (
	"testing"

	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
)

func mustTestCodec(t *testing.T, key string) *security.Codec {
	t.Helper()
	codec, err := security.NewCodec(5, key)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return codec
}

func TestSetNodeCodecsAttributesSessions(t *testing.T) {
	base := mustTestCodec(t, "shared-key-for-node-codecs-test-1")
	srv := &Server{codecs: []*security.Codec{base}}
	if got := srv.nodeIDForCodec(base); got != "" {
		t.Fatalf("single-key mode must report empty node ID, got %q", got)
	}

	nodeA := mustTestCodec(t, "node-a-key-for-node-codecs-test-1")
	nodeB := mustTestCodec(t, "node-b-key-for-node-codecs-test-1")
	srv.SetNodeCodecs([]*security.Codec{nodeA, nodeB}, []string{"node-a", "node-b"})
	if len(srv.codecs) != 2 || srv.codecs[0] != nodeA || srv.codecs[1] != nodeB {
		t.Fatal("SetNodeCodecs did not install the registry codecs")
	}
	if got := srv.nodeIDForCodec(nodeA); got != "node-a" {
		t.Fatalf("nodeA: got %q, want node-a", got)
	}
	if got := srv.nodeIDForCodec(nodeB); got != "node-b" {
		t.Fatalf("nodeB: got %q, want node-b", got)
	}
	if got := srv.nodeIDForCodec(base); got != "" {
		t.Fatalf("unregistered codec: got %q, want empty", got)
	}
	if got := srv.nodeIDForCodec(nil); got != "" {
		t.Fatalf("nil codec: got %q, want empty", got)
	}
}

func TestSetNodeCodecsRejectsMismatchedInput(t *testing.T) {
	base := mustTestCodec(t, "shared-key-for-node-codecs-test-2")
	srv := &Server{codecs: []*security.Codec{base}}
	other := mustTestCodec(t, "node-c-key-for-node-codecs-test-2")

	srv.SetNodeCodecs([]*security.Codec{other}, []string{"a", "b"})
	if len(srv.codecs) != 1 || srv.codecs[0] != base {
		t.Fatal("length mismatch must leave the codec set untouched")
	}
	srv.SetNodeCodecs(nil, nil)
	if len(srv.codecs) != 1 || srv.codecs[0] != base {
		t.Fatal("empty input must leave the codec set untouched")
	}
	srv.SetNodeCodecs([]*security.Codec{nil}, []string{"x"})
	if len(srv.codecs) != 1 || srv.codecs[0] != base {
		t.Fatal("nil codec must leave the codec set untouched")
	}
	srv.SetNodeCodecs([]*security.Codec{other, mustTestCodec(t, "node-d-key-for-node-codecs-test-2")}, []string{"only-one"})
	if len(srv.codecs) != 1 || srv.codecs[0] != base {
		t.Fatal("more codecs than node IDs must leave the codec set untouched")
	}
}

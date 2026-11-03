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
	srv := &Server{}
	srv.installed.Store(&codecSet{codecs: []*security.Codec{base}})
	if got := srv.nodeIDForCodec(base); got != "" {
		t.Fatalf("single-key mode must report empty node ID, got %q", got)
	}

	nodeA := mustTestCodec(t, "node-a-key-for-node-codecs-test-1")
	nodeB := mustTestCodec(t, "node-b-key-for-node-codecs-test-1")
	srv.SetNodeCodecs([]*security.Codec{nodeA, nodeB}, []string{"node-a", "node-b"})
	snapshot := srv.codecSnapshot()
	if len(snapshot) != 2 || snapshot[0] != nodeA || snapshot[1] != nodeB {
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
	srv := &Server{}
	srv.installed.Store(&codecSet{codecs: []*security.Codec{base}})
	other := mustTestCodec(t, "node-c-key-for-node-codecs-test-2")

	assertUntouched := func() {
		t.Helper()
		snapshot := srv.codecSnapshot()
		if len(snapshot) != 1 || snapshot[0] != base {
			t.Fatal("rejected input must leave the codec set untouched")
		}
	}

	srv.SetNodeCodecs([]*security.Codec{other}, []string{"a", "b"})
	assertUntouched()
	srv.SetNodeCodecs(nil, nil)
	assertUntouched()
	srv.SetNodeCodecs([]*security.Codec{nil}, []string{"x"})
	assertUntouched()
	srv.SetNodeCodecs([]*security.Codec{other, mustTestCodec(t, "node-d-key-for-node-codecs-test-2")}, []string{"only-one"})
	assertUntouched()
}

func TestReloadNodeCodecsSwapsAtomically(t *testing.T) {
	base := mustTestCodec(t, "shared-key-for-node-codecs-test-3")
	srv := &Server{}
	srv.installed.Store(&codecSet{codecs: []*security.Codec{base}})

	nodeA := mustTestCodec(t, "node-a-key-for-node-codecs-test-3")
	nodeB := mustTestCodec(t, "node-b-key-for-node-codecs-test-3")
	if err := srv.ReloadNodeCodecs([]*security.Codec{nodeA, nodeB}, []string{"node-a", "node-b"}); err != nil {
		t.Fatalf("ReloadNodeCodecs: %v", err)
	}
	if got := srv.nodeIDForCodec(nodeA); got != "node-a" {
		t.Fatalf("nodeA after reload: got %q", got)
	}
	if got := srv.nodeIDForCodec(base); got != "" {
		t.Fatalf("old codec after reload: got %q, want empty", got)
	}
	// The preferred-codec trial index resets: a stale index from a
	// longer set must not leak into the new set's trial order.
	srv.preferredCodec.Store(1)
	if err := srv.ReloadNodeCodecs([]*security.Codec{nodeA}, []string{"node-a"}); err != nil {
		t.Fatalf("ReloadNodeCodecs: %v", err)
	}
	if got := srv.preferredCodec.Load(); got != 0 {
		t.Fatalf("preferred codec after reload = %d, want 0", got)
	}
	// Rejected reloads report errors and leave the set untouched.
	if err := srv.ReloadNodeCodecs(nil, nil); err == nil {
		t.Error("empty reload must report an error")
	}
	if err := srv.ReloadNodeCodecs([]*security.Codec{nodeA}, []string{"a", "b"}); err == nil {
		t.Error("mismatched reload must report an error")
	}
	if got := srv.nodeIDForCodec(nodeA); got != "node-a" {
		t.Fatalf("nodeA after rejected reloads: got %q", got)
	}
	// A nil server never panics.
	var nilSrv *Server
	if err := nilSrv.ReloadNodeCodecs([]*security.Codec{nodeA}, []string{"node-a"}); err == nil {
		t.Error("nil server reload must report an error")
	}
	if got := nilSrv.codecSnapshot(); got != nil {
		t.Errorf("nil server snapshot = %v, want nil", got)
	}
}

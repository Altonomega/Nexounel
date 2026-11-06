package udpserver

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/config"
	"github.com/Altonomega/Nexounel/core/internal/enroll"
	Enums "github.com/Altonomega/Nexounel/core/internal/enums"
	"github.com/Altonomega/Nexounel/core/internal/security"
	VpnProto "github.com/Altonomega/Nexounel/core/internal/vpnproto"
)

func testBootstrapServer(t *testing.T) *Server {
	t.Helper()
	return &Server{cfg: config.ServerConfig{DataEncryptionMethod: 5}}
}

func TestBootstrapKeyAddRemoveLookup(t *testing.T) {
	srv := testBootstrapServer(t)
	fp := strings.Repeat("ab", 32)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	if err := srv.AddBootstrapKey(fp, key, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("AddBootstrapKey: %v", err)
	}
	codec, err := security.NewCodec(5, hex.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	// The stored codec is a fresh build from the same key string:
	// lookup is by pointer identity against the snapshot, so
	// resolve it through the snapshot instead of comparing builds.
	set := srv.bootstrapSnapshot()
	if set == nil || len(set.entries) != 1 {
		t.Fatalf("snapshot = %+v", set)
	}
	gotFP, ok := srv.bootstrapFingerprintForCodec(set.entries[0].codec)
	if !ok || gotFP != fp {
		t.Fatalf("lookup = %q, %v", gotFP, ok)
	}
	if _, ok := srv.bootstrapFingerprintForCodec(codec); ok {
		t.Fatal("a separately built codec with the same key must not match: identity is by snapshot pointer")
	}
	if err := srv.RemoveBootstrapKey(fp); err != nil {
		t.Fatalf("RemoveBootstrapKey: %v", err)
	}
	if _, ok := srv.bootstrapFingerprintForCodec(set.entries[0].codec); ok {
		t.Fatal("removed key must not authenticate")
	}
	// Removing an unknown fingerprint succeeds.
	if err := srv.RemoveBootstrapKey(fp); err != nil {
		t.Fatalf("removing an unknown fingerprint: %v", err)
	}
}

func TestBootstrapKeyRejectsBadInput(t *testing.T) {
	srv := testBootstrapServer(t)
	key := make([]byte, 32)
	cases := []struct {
		name string
		fp   string
		key  []byte
		exp  time.Time
	}{
		{"short fingerprint", "abc", key, time.Now().Add(time.Hour)},
		{"uppercase fingerprint", strings.ToUpper(strings.Repeat("ab", 32)), key, time.Now().Add(time.Hour)},
		{"short key", strings.Repeat("ab", 32), make([]byte, 16), time.Now().Add(time.Hour)},
		{"past expiry", strings.Repeat("ab", 32), key, time.Now().Add(-time.Hour)},
	}
	for _, tc := range cases {
		if err := srv.AddBootstrapKey(tc.fp, tc.key, tc.exp); err == nil {
			t.Errorf("%s: must be refused", tc.name)
		}
	}
	if err := srv.RemoveBootstrapKey("nope"); err == nil {
		t.Error("malformed fingerprint removal must be refused")
	}
}

func TestBootstrapTrialDecryptsTokenKeyedFrames(t *testing.T) {
	token, err := enroll.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := enroll.BootstrapKey(token)
	if err != nil {
		t.Fatal(err)
	}
	keyHex, err := enroll.BootstrapKeyString(token)
	if err != nil {
		t.Fatal(err)
	}
	fp := enroll.TokenFingerprint(token)

	srv := testBootstrapServer(t)
	// Node codec set: a different key that must NOT authenticate
	// the bootstrap frame.
	nodeCodec := mustTestCodec(t, "node-key-for-bootstrap-trial-test")
	srv.installed.Store(&codecSet{codecs: []*security.Codec{nodeCodec}})
	if err := srv.AddBootstrapKey(fp, rawKey, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("AddBootstrapKey: %v", err)
	}

	// The node-side codec, built exactly as enroll mode builds it
	// (BootstrapKeyString as the key string).
	nodeSideCodec, err := security.NewCodec(5, keyHex)
	if err != nil {
		t.Fatal(err)
	}
	initPayload := make([]byte, sessionInitDataSize)
	labels, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		PacketType: Enums.PACKET_SESSION_INIT,
		Payload:    initPayload,
	}, nodeSideCodec)
	if err != nil {
		t.Fatal(err)
	}
	packet, gotFP, ok := srv.tryBootstrapDecrypt(labels)
	if !ok {
		t.Fatal("bootstrap trial must authenticate the token-keyed frame")
	}
	if gotFP != fp {
		t.Fatalf("fingerprint = %q, want %q", gotFP, fp)
	}
	if packet.PacketType != Enums.PACKET_SESSION_INIT {
		t.Fatalf("packet type = %d", packet.PacketType)
	}
	if _, ok := srv.bootstrapFingerprintForCodec(packet.IngressCodec); !ok {
		t.Fatal("the trial packet's codec must attribute to the bootstrap key")
	}

	// A frame under an unrelated key authenticates under nothing.
	attackerCodec := mustTestCodec(t, "attacker-key-for-bootstrap-trial-test")
	attackerLabels, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		PacketType: Enums.PACKET_SESSION_INIT,
		Payload:    initPayload,
	}, attackerCodec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := srv.tryBootstrapDecrypt(attackerLabels); ok {
		t.Fatal("attacker frame must not authenticate under the bootstrap set")
	}
}

func TestBootstrapTrialRejectsExpiredKeys(t *testing.T) {
	token, err := enroll.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := enroll.BootstrapKey(token)
	if err != nil {
		t.Fatal(err)
	}
	keyHex, err := enroll.BootstrapKeyString(token)
	if err != nil {
		t.Fatal(err)
	}
	fp := enroll.TokenFingerprint(token)

	srv := testBootstrapServer(t)
	// Install with a short TTL, then let it lapse. Add refuses
	// past expiries, so install valid and rewrite the snapshot
	// entry's expiry directly (test-only mutation of the
	// immutable snapshot's entry is avoided: rebuild instead).
	if err := srv.AddBootstrapKey(fp, rawKey, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	st := srv.bootstrapState()
	st.mu.Lock()
	set := st.snapshot.Load()
	entries := append([]bootstrapKeyEntry(nil), set.entries...)
	entries[0].expiresAt = time.Now().Add(-time.Minute)
	st.snapshot.Store(&bootstrapCodecSet{entries: entries})
	st.mu.Unlock()

	nodeSideCodec, err := security.NewCodec(5, keyHex)
	if err != nil {
		t.Fatal(err)
	}
	labels, err := VpnProto.BuildEncoded(VpnProto.BuildOptions{
		PacketType: Enums.PACKET_SESSION_INIT,
		Payload:    make([]byte, sessionInitDataSize),
	}, nodeSideCodec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := srv.tryBootstrapDecrypt(labels); ok {
		t.Fatal("expired bootstrap key must not authenticate")
	}
	if _, ok := srv.bootstrapFingerprintForCodec(set.entries[0].codec); ok {
		t.Fatal("expired bootstrap key must not attribute")
	}
}

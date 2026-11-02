package panel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct horse example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected PHC prefix: %q", hash)
	}
	ok, err := VerifyPassword(hash, "correct horse example")
	if err != nil || !ok {
		t.Fatalf("correct password rejected: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword(hash, "wrong password")
	if err != nil || ok {
		t.Fatalf("wrong password accepted: ok=%v err=%v", ok, err)
	}
	if _, err := VerifyPassword("not-a-hash", "x"); err == nil {
		t.Fatal("malformed hash accepted")
	}
	// Distinct salts: two hashes of the same password must differ.
	hash2, err := HashPassword("correct horse example")
	if err != nil {
		t.Fatal(err)
	}
	if hash == hash2 {
		t.Fatal("identical hashes: salt reuse suspected")
	}
}

func TestSessionStoreLifecycle(t *testing.T) {
	store := NewSessionStore()
	sess, err := store.Create()
	if err != nil {
		t.Fatal(err)
	}
	if sess.Authenticated {
		t.Fatal("new session must not be authenticated")
	}
	got, ok := store.Get(sess.Token)
	if !ok || got != sess {
		t.Fatal("created session not retrievable")
	}
	oldToken := sess.Token
	if !ValidCSRF(sess, sess.CSRFToken) || ValidCSRF(sess, "bogus") || ValidCSRF(sess, sess.CSRFToken+"x") {
		t.Fatal("CSRF validation wrong")
	}
	newToken, err := store.Authenticate(sess.Token, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(oldToken); ok {
		t.Fatal("old token still valid after rotation")
	}
	got, ok = store.Get(newToken)
	if !ok || !got.Authenticated || got.Username != "admin" {
		t.Fatal("rotated session not authenticated")
	}
	store.Invalidate(newToken)
	if _, ok := store.Get(newToken); ok {
		t.Fatal("invalidated session still valid")
	}
}

func TestRateLimiterLockout(t *testing.T) {
	limiter := NewRateLimiter()
	ip, user := "203.0.113.10", "admin"
	for i := 0; i < 4; i++ {
		limiter.RecordFailure(ip, user)
		if limiter.Locked(ip, user) {
			t.Fatalf("locked after %d failures", i+1)
		}
	}
	limiter.RecordFailure(ip, user)
	if !limiter.Locked(ip, user) {
		t.Fatal("not locked after 5 failures")
	}
	// A different username from the same IP is not locked.
	if limiter.Locked(ip, "other") {
		t.Fatal("lockout leaked to another username")
	}
	limiter.RecordSuccess(ip, user)
	// Success clears state only after lockout expires in this design:
	// RecordSuccess deletes the entry outright, so a fresh failure
	// sequence is required to lock again.
	if limiter.Locked(ip, user) {
		t.Fatal("lockout persisted after success clear")
	}
}

func TestLogRedaction(t *testing.T) {
	lines := []string{
		"server started",
		"node key fingerprint: ab12cd34",
		"password = hunter2 example",
		"Authorization: Bearer test-key-abc",
		"the secret token was rotated",
		"normal line mentioning keyboard layout",
	}
	// "keyboard" contains "key" but not as a word; the word-boundary
	// pattern must keep it. A line mentioning the word "key" itself
	// (even a fingerprint line) is dropped, per the spec rule.
	kept := RedactLogLines(lines)
	for _, line := range kept {
		if strings.Contains(line, "hunter2") || strings.Contains(line, "Bearer") || strings.Contains(line, "secret token") {
			t.Fatalf("secret line kept: %q", line)
		}
	}
	if len(kept) != 2 {
		t.Fatalf("expected 2 kept lines, got %d: %v", len(kept), kept)
	}
	if !ShouldDropLogLine("my PassWord is test-key-x") {
		t.Fatal("password line not dropped")
	}
}

func TestScrubSecrets(t *testing.T) {
	out := ScrubSecrets("connecting with password hunter2 and host 203.0.113.1", []string{"hunter2"})
	if strings.Contains(out, "hunter2") || !strings.Contains(out, "[redacted]") {
		t.Fatalf("secret not scrubbed: %q", out)
	}
}

func TestConfigSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nexounel-panel.toml")
	cfg, err := CreateInitialConfig(path, false, "admin", "example-password")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebPath == "" || len(cfg.SessionKey) != 64 {
		t.Fatalf("generated config incomplete: %+v", cfg)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %o, want 0600", info.Mode().Perm())
	}
	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Username != "admin" || loaded.WebPath != cfg.WebPath || loaded.SessionKey != cfg.SessionKey {
		t.Fatalf("round trip mismatch: %+v vs %+v", loaded, cfg)
	}
	if err := ValidateConfig(loaded); err != nil {
		t.Fatalf("saved config failed validation: %v", err)
	}
	// Refuse overwrite without -force, allow with it.
	if _, err := CreateInitialConfig(path, false, "admin", "other"); err == nil {
		t.Fatal("overwrite without -force allowed")
	}
	if _, err := CreateInitialConfig(path, true, "admin", "other"); err != nil {
		t.Fatalf("overwrite with -force failed: %v", err)
	}
}

func TestValidateWebPath(t *testing.T) {
	for _, bad := range []string{"", "/", "abc", "/a/b", "/a b", "/a?b"} {
		if err := ValidateWebPath(bad); err == nil {
			t.Fatalf("web path %q accepted", bad)
		}
	}
	if err := ValidateWebPath("/Abc123-_~."); err != nil {
		t.Fatalf("valid web path rejected: %v", err)
	}
	webPath, err := GenerateWebPath()
	if err != nil {
		t.Fatal(err)
	}
	if len(webPath) != 33 || !strings.HasPrefix(webPath, "/") {
		t.Fatalf("generated web path malformed: %q", webPath)
	}
	if err := ValidateWebPath(webPath); err != nil {
		t.Fatalf("generated web path failed validation: %v", err)
	}
}

func TestConfigValidationRejectsBadValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.WebPath = "/test-path-example"
	cfg.Username = "admin"
	hash, err := HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	cfg.PasswordHash = hash
	cfg.SessionKey = "zzzz"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("non-hex session key accepted")
	}
	cfg.SessionKey, _ = GenerateSessionKey()
	cfg.ListenAddr = "not-an-address"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("bad listen address accepted")
	}
}

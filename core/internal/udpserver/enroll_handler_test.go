package udpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/enroll"
)

type fakeEnrollIssuer struct {
	mu       sync.Mutex
	calls    int
	response enroll.EnrollmentResponse
	err      error
	lastFP   string
	lastReq  enroll.EnrollmentRequest
}

func (f *fakeEnrollIssuer) Issue(ctx context.Context, fingerprint string, req enroll.EnrollmentRequest) (enroll.EnrollmentResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastFP = fingerprint
	f.lastReq = req
	return f.response, f.err
}

func (f *fakeEnrollIssuer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func runEnrollHandler(t *testing.T, srv *Server, record *sessionRecord, reqBytes []byte) enroll.EnrollmentResponse {
	t.Helper()
	clientEnd, handlerEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.serveEnrollmentStream(handlerEnd, record)
	}()
	t.Cleanup(func() {
		_ = clientEnd.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("enrollment handler did not return")
		}
	})
	_ = clientEnd.SetDeadline(time.Now().Add(5 * time.Second))
	if reqBytes != nil {
		// Write concurrently: the handler may fail closed
		// (no issuer, missing fingerprint) before reading any
		// request bytes, in which case the write fails on the
		// closed pipe and the response is authoritative.
		writeDone := make(chan struct{})
		go func() {
			defer close(writeDone)
			_, _ = clientEnd.Write(reqBytes)
		}()
		defer func() { <-writeDone }()
	}
	var raw json.RawMessage
	if err := json.NewDecoder(clientEnd).Decode(&raw); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	resp, err := enroll.ParseResponse(raw)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	return resp
}

func TestEnrollHandlerRelaysSuccessAndDropsKey(t *testing.T) {
	srv := testBootstrapServer(t)
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := srv.AddBootstrapKey(fp, key, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	issuer := &fakeEnrollIssuer{response: enroll.EnrollmentResponse{
		NodeID: "node-1", NodeKey: "node-key", NodeConfig: "node-config", MeshControlSecret: "secret",
	}}
	srv.SetEnrollmentIssuer(issuer)
	record := &sessionRecord{ID: 300, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: fp}

	reqBytes, err := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: "node-1", Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	resp := runEnrollHandler(t, srv, record, reqBytes)
	if resp.ErrorCode != "" {
		t.Fatalf("error code = %q (%s)", resp.ErrorCode, resp.Error)
	}
	if resp.NodeID != "node-1" || resp.NodeKey != "node-key" || resp.NodeConfig != "node-config" || resp.MeshControlSecret != "secret" {
		t.Fatalf("response = %+v", resp)
	}
	if issuer.callCount() != 1 || issuer.lastFP != fp || issuer.lastReq.NodeID != "node-1" {
		t.Fatalf("issuer calls = %d, fp = %q, req = %+v", issuer.callCount(), issuer.lastFP, issuer.lastReq)
	}
	// Success drops the bootstrap key: the token cannot enroll twice.
	if set := srv.bootstrapSnapshot(); set != nil {
		for _, e := range set.entries {
			if e.fingerprint == fp {
				t.Fatal("bootstrap key must be dropped after successful enrollment")
			}
		}
	}
}

func TestEnrollHandlerRelaysRefusalVerbatim(t *testing.T) {
	srv := testBootstrapServer(t)
	issuer := &fakeEnrollIssuer{response: enroll.EnrollmentResponse{
		ErrorCode: enroll.ErrCodeBurnedToken, Error: "token burned",
	}}
	srv.SetEnrollmentIssuer(issuer)
	fp := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	record := &sessionRecord{ID: 301, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: fp}
	reqBytes, _ := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: "node-1", Token: "test-token"})
	resp := runEnrollHandler(t, srv, record, reqBytes)
	if resp.ErrorCode != enroll.ErrCodeBurnedToken {
		t.Fatalf("error code = %q, want %q", resp.ErrorCode, enroll.ErrCodeBurnedToken)
	}
}

func TestEnrollHandlerFailsClosedWithoutIssuer(t *testing.T) {
	srv := testBootstrapServer(t)
	// No issuer configured: transient, and the (absent) issuer is
	// never consulted.
	record := &sessionRecord{ID: 302, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	reqBytes, _ := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: "node-1", Token: "test-token"})
	resp := runEnrollHandler(t, srv, record, reqBytes)
	if resp.ErrorCode != enroll.ErrCodeFailed {
		t.Fatalf("error code = %q, want transient %q", resp.ErrorCode, enroll.ErrCodeFailed)
	}
}

func TestEnrollHandlerMapsIssuerOutageToTransient(t *testing.T) {
	srv := testBootstrapServer(t)
	issuer := &fakeEnrollIssuer{err: enroll.ErrIssuerUnavailable}
	srv.SetEnrollmentIssuer(issuer)
	record := &sessionRecord{ID: 303, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	reqBytes, _ := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: "node-1", Token: "test-token"})
	resp := runEnrollHandler(t, srv, record, reqBytes)
	if resp.ErrorCode != enroll.ErrCodeFailed {
		t.Fatalf("error code = %q, want transient %q", resp.ErrorCode, enroll.ErrCodeFailed)
	}
	if enroll.PermanentErrorCode(resp.ErrorCode) {
		t.Fatal("issuer outage must be transient, not permanent")
	}
}

func TestEnrollHandlerRejectsMalformedRequests(t *testing.T) {
	srv := testBootstrapServer(t)
	issuer := &fakeEnrollIssuer{}
	srv.SetEnrollmentIssuer(issuer)
	record := &sessionRecord{ID: 304, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	for name, reqBytes := range map[string][]byte{
		"not json":    []byte("{oops"),
		"wrong capa":  []byte(`{"version":1,"node_id":"node-1","token":"t","capability":"bogus"}`),
		"wrong ver":   []byte(`{"version":99,"node_id":"node-1","token":"t","capability":"nexounel-bootstrap-v1"}`),
		"empty node":  []byte(`{"version":1,"node_id":"","token":"t","capability":"nexounel-bootstrap-v1"}`),
		"bad node id": []byte(`{"version":1,"node_id":"bad id!","token":"t","capability":"nexounel-bootstrap-v1"}`),
	} {
		resp := runEnrollHandler(t, srv, record, reqBytes)
		if resp.ErrorCode != enroll.ErrCodeFailed {
			t.Errorf("%s: error code = %q, want transient", name, resp.ErrorCode)
		}
	}
	if issuer.callCount() != 0 {
		t.Fatalf("malformed requests must never reach the issuer (calls = %d)", issuer.callCount())
	}
}

func TestEnrollHandlerRejectsMissingFingerprint(t *testing.T) {
	srv := testBootstrapServer(t)
	issuer := &fakeEnrollIssuer{}
	srv.SetEnrollmentIssuer(issuer)
	// A bootstrap session always carries a fingerprint; a record
	// without one is a programming error — fail closed.
	record := &sessionRecord{ID: 305, Kind: enroll.SessionKindBootstrap}
	reqBytes, _ := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: "node-1", Token: "test-token"})
	resp := runEnrollHandler(t, srv, record, reqBytes)
	if resp.ErrorCode != enroll.ErrCodeFailed {
		t.Fatalf("error code = %q, want transient", resp.ErrorCode)
	}
	if issuer.callCount() != 0 {
		t.Fatal("missing-fingerprint requests must never reach the issuer")
	}
}

func TestEnrollRateLimiter(t *testing.T) {
	var l enrollmentRateLimiter
	now := time.Now()
	for i := 0; i < maxEnrollmentAttemptsPerMinute; i++ {
		if !l.allow(now) {
			t.Fatalf("attempt %d must be allowed", i)
		}
	}
	if l.allow(now) {
		t.Fatal("attempt past the cap must be limited")
	}
	if !l.allow(now.Add(61 * time.Second)) {
		t.Fatal("a new window must allow attempts again")
	}
}

var errFakeIssuerOther = errors.New("fake issuer internal error")

func TestEnrollHandlerMapsOtherIssuerErrorsToTransient(t *testing.T) {
	srv := testBootstrapServer(t)
	issuer := &fakeEnrollIssuer{err: errFakeIssuerOther}
	srv.SetEnrollmentIssuer(issuer)
	record := &sessionRecord{ID: 306, Kind: enroll.SessionKindBootstrap, BootstrapFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	reqBytes, _ := enroll.MarshalRequest(enroll.EnrollmentRequest{NodeID: "node-1", Token: "test-token"})
	resp := runEnrollHandler(t, srv, record, reqBytes)
	if resp.ErrorCode != enroll.ErrCodeFailed {
		t.Fatalf("error code = %q, want transient", resp.ErrorCode)
	}
}

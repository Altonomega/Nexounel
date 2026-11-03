package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPIssuerRoundTrip(t *testing.T) {
	want := EnrollmentResponse{NodeID: "node-1", NodeKey: "k", NodeConfig: "c", MeshControlSecret: "s"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		var wire issueWireRequest
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Fatalf("decode wire request: %v", err)
		}
		if wire.Fingerprint != "fp" {
			t.Errorf("fingerprint = %q", wire.Fingerprint)
		}
		if wire.Request.NodeID != "node-1" || wire.Request.Token != "tok" || wire.Request.Capability != CapabilityLabel {
			t.Errorf("request = %+v", wire.Request)
		}
		data, _ := MarshalResponse(want)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	issuer := HTTPIssuer{Endpoint: srv.URL}
	got, err := issuer.Issue(context.Background(), "fp", EnrollmentRequest{NodeID: "node-1", Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeID != want.NodeID || got.NodeKey != want.NodeKey || got.NodeConfig != want.NodeConfig || got.MeshControlSecret != want.MeshControlSecret {
		t.Fatalf("response = %+v, want %+v", got, want)
	}
}

func TestHTTPIssuerRefusesNonLoopback(t *testing.T) {
	for _, endpoint := range []string{"", "https://panel.example.com/enroll", "http://192.0.2.1/enroll", "http://mother/enroll"} {
		issuer := HTTPIssuer{Endpoint: endpoint}
		_, err := issuer.Issue(context.Background(), "fp", EnrollmentRequest{NodeID: "n", Token: "t"})
		if !errors.Is(err, ErrIssuerUnavailable) {
			t.Errorf("endpoint %q: err = %v, want ErrIssuerUnavailable", endpoint, err)
		}
	}
}

func TestHTTPIssuerMapsFailuresToUnavailable(t *testing.T) {
	// Panel down: connection refused.
	issuer := HTTPIssuer{Endpoint: "http://127.0.0.1:1/enroll"}
	_, err := issuer.Issue(context.Background(), "fp", EnrollmentRequest{NodeID: "n", Token: "t"})
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("refused connection: err = %v", err)
	}
	// Panel answers non-200.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	issuer = HTTPIssuer{Endpoint: srv.URL}
	_, err = issuer.Issue(context.Background(), "fp", EnrollmentRequest{NodeID: "n", Token: "t"})
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("HTTP 500: err = %v", err)
	}
	// Panel answers malformed JSON.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	defer srv2.Close()
	issuer = HTTPIssuer{Endpoint: srv2.URL}
	_, err = issuer.Issue(context.Background(), "fp", EnrollmentRequest{NodeID: "n", Token: "t"})
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("malformed JSON: err = %v", err)
	}
}

func TestPermanentErrorCode(t *testing.T) {
	for _, code := range []string{ErrCodeUnknownToken, ErrCodeExpiredToken, ErrCodeUsedToken, ErrCodeBurnedToken, ErrCodeRevokedToken} {
		if !PermanentErrorCode(code) {
			t.Errorf("%s must be permanent", code)
		}
	}
	for _, code := range []string{"", ErrCodeFailed, "something-else"} {
		if PermanentErrorCode(code) {
			t.Errorf("%s must be transient", code)
		}
	}
}

func TestIssuerHonorsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	issuer := HTTPIssuer{Endpoint: srv.URL}
	_, err := issuer.Issue(ctx, "fp", EnrollmentRequest{NodeID: "n", Token: "t"})
	if err == nil || !strings.Contains(err.Error(), "context") {
		t.Fatalf("err = %v, want a context error", err)
	}
}

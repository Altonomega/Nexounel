package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudflareAuth carries one wizard run's Cloudflare authorization. It is
// passed per call and never stored on the client, on disk, or in logs.
// Callers zero the key/token bytes after use where feasible.
type CloudflareAuth struct {
	Email string
	Key   []byte // Global API key (used with Email)
	Token []byte // Scoped API token (Bearer)
}

// Valid reports whether the auth carries a usable authorization style.
func (a CloudflareAuth) Valid() bool {
	return (a.Email != "" && len(a.Key) > 0) || len(a.Token) > 0
}

// Zero overwrites the secret bytes held by this auth value.
func (a *CloudflareAuth) Zero() {
	if a == nil {
		return
	}
	for i := range a.Key {
		a.Key[i] = 0
	}
	for i := range a.Token {
		a.Token[i] = 0
	}
	a.Key = nil
	a.Token = nil
}

// DNSRecord is one Cloudflare DNS record to create.
type DNSRecord struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

// CloudflareClient talks to the Cloudflare API v4. It exposes list, create
// and verify ONLY: there is deliberately no method that deletes, updates
// or patches a record, and a test asserts that invariant by reflection.
type CloudflareClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewCloudflareClient builds a client for the given API base URL
// (default https://api.cloudflare.com/client/v4). A nil HTTP client gets
// a 15s-timeout default.
func NewCloudflareClient(baseURL string, httpClient *http.Client) *CloudflareClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://api.cloudflare.com/client/v4"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &CloudflareClient{baseURL: strings.TrimSuffix(baseURL, "/"), httpClient: httpClient}
}

// ListZones returns the zone ID for an active zone matching domain.
func (c *CloudflareClient) ListZones(ctx context.Context, auth CloudflareAuth, domain string) (string, error) {
	if !auth.Valid() {
		return "", fmt.Errorf("cloudflare authorization is required")
	}
	url := c.baseURL + "/zones?name=" + urlQueryEscape(domain) + "&status=active&per_page=1"
	var payload struct {
		Success bool `json:"success"`
		Errors  []apiError
		Result  []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := doAPIRequest(c, ctx, auth, http.MethodGet, url, nil, &payload); err != nil {
		return "", err
	}
	if !payload.Success {
		return "", fmt.Errorf("cloudflare list zones failed: %s", formatAPIErrors(payload.Errors))
	}
	if len(payload.Result) == 0 {
		return "", fmt.Errorf("cloudflare: no active zone found for domain %q", domain)
	}
	return payload.Result[0].ID, nil
}

// CreateDNSRecord creates one DNS record in the given zone and returns
// the new record ID.
func (c *CloudflareClient) CreateDNSRecord(ctx context.Context, auth CloudflareAuth, zoneID string, record DNSRecord) (string, error) {
	if !auth.Valid() {
		return "", fmt.Errorf("cloudflare authorization is required")
	}
	if strings.TrimSpace(zoneID) == "" {
		return "", fmt.Errorf("zone id is required")
	}
	body, err := json.Marshal(record)
	if err != nil {
		return "", fmt.Errorf("encode DNS record: %w", err)
	}
	var payload struct {
		Success bool `json:"success"`
		Errors  []apiError
		Result  struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := doAPIRequest(c, ctx, auth, http.MethodPost, c.baseURL+"/zones/"+zoneID+"/dns_records", body, &payload); err != nil {
		return "", err
	}
	if !payload.Success {
		return "", fmt.Errorf("cloudflare create DNS record failed: %s", formatAPIErrors(payload.Errors))
	}
	if payload.Result.ID == "" {
		return "", fmt.Errorf("cloudflare create DNS record returned no record id")
	}
	return payload.Result.ID, nil
}

// VerifyRecords checks the wizard DNS records against the public
// resolvers using the shared DNS verification.
func (c *CloudflareClient) VerifyRecords(ctx context.Context, resolver DNSResolver, domain, subdomain, motherIP string) []RecordVerification {
	return VerifyDNSRecords(ctx, resolver, domain, subdomain, motherIP)
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func formatAPIErrors(errs []apiError) string {
	if len(errs) == 0 {
		return "unknown error"
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("%d: %s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}

// doAPIRequest performs one Cloudflare API call. It is a plain function,
// not a method, so the client's method surface stays list/create/verify.
// It never logs: request bodies and headers may carry authorization.
func doAPIRequest(c *CloudflareClient, ctx context.Context, auth CloudflareAuth, method, url string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return fmt.Errorf("build cloudflare request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if len(auth.Token) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(auth.Token))
	} else {
		req.Header.Set("X-Auth-Email", auth.Email)
		req.Header.Set("X-Auth-Key", string(auth.Key))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read cloudflare response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("cloudflare request returned status %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("parse cloudflare response: %w", err)
	}
	return nil
}

func urlQueryEscape(s string) string {
	// Domains need no general query escaping beyond the characters a
	// hostname may contain; keep this dependency-free and explicit.
	replacer := strings.NewReplacer(" ", "%20", "&", "%26", "?", "%3F", "#", "%23", "+", "%2B")
	return replacer.Replace(s)
}

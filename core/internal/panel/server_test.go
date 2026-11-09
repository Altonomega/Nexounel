package panel

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var csrfPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

type testEnv struct {
	t         *testing.T
	dir       string
	cfg       Config
	cfgPath   string
	server    *Server
	registry  string
	factory   *mockFactory
	runnerLog *[]string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "nexounel-panel.toml")
	cfg, err := CreateInitialConfig(cfgPath, false, "admin", "example-password")
	if err != nil {
		t.Fatal(err)
	}
	registry := filepath.Join(dir, "nodes.toml")
	if err := os.WriteFile(registry, []byte("[[nodes]]\nid = \"node-1\"\nkey = \""+validTestKey(1)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.RegistryFile = registry
	cfg.MetricsAddr = "127.0.0.1:1" // down by default; tests override
	cfg.NodeConfig = filepath.Join(dir, "missing-node.toml")
	cfg.NodeBinary = filepath.Join(dir, "nexounel-node")
	if err := os.WriteFile(cfg.NodeBinary, []byte("fake"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.ResolversFile = filepath.Join(dir, "missing-resolvers.txt")
	cfg.LogTailLines = 10
	srv := NewServer(cfg, cfgPath, nil)
	srv.dnsResolver = &mockResolver{
		aRecords:  map[string][]string{"ns1.example.invalid": {"203.0.113.10"}},
		nsRecords: map[string][]string{"v.example.invalid": {"ns1.example.invalid."}},
	}
	var runnerLog []string
	srv.runner = func(ctx context.Context, name string, args ...string) (string, error) {
		runnerLog = append(runnerLog, name+" "+strings.Join(args, " "))
		if name == "journalctl" {
			return "server started\npassword = planted-secret-example\nplain line\n", nil
		}
		if name == "systemctl" {
			return "active\n", nil
		}
		return "", fmt.Errorf("unexpected command %s", name)
	}
	env := &testEnv{t: t, dir: dir, cfg: cfg, cfgPath: cfgPath, server: srv, registry: registry, runnerLog: &runnerLog}
	srv.factoryForAddr = func(addr string) TransportFactory {
		return env.factory.factory
	}
	return env
}

func (e *testEnv) do(method, path string, form url.Values, cookie *http.Cookie) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.RemoteAddr = "203.0.113.99:12345"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.server.ServeHTTP(rec, req)
	return rec
}

func (e *testEnv) loginCookie(t *testing.T) (*http.Cookie, string) {
	t.Helper()
	rec := e.do(http.MethodGet, e.cfg.WebPath+"/login", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login GET status %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session cookie on login page")
	}
	cookie := cookies[0]
	csrf := csrfPattern.FindStringSubmatch(rec.Body.String())
	if csrf == nil {
		t.Fatal("no CSRF token on login page")
	}
	form := url.Values{"username": {"admin"}, "password": {"example-password"}, "csrf_token": {csrf[1]}}
	rec = e.do(http.MethodPost, e.cfg.WebPath+"/login", form, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("login POST status %d body %s", rec.Code, rec.Body.String())
	}
	newCookies := rec.Result().Cookies()
	if len(newCookies) == 0 {
		t.Fatal("no cookie after login")
	}
	return newCookies[0], csrf[1]
}

func (e *testEnv) authed(t *testing.T) *http.Cookie {
	t.Helper()
	cookie, _ := e.loginCookie(t)
	return cookie
}

func (e *testEnv) csrfFor(t *testing.T, cookie *http.Cookie, path string) string {
	t.Helper()
	rec := e.do(http.MethodGet, path, nil, cookie)
	m := csrfPattern.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no CSRF token on %s", path)
	}
	return m[1]
}

func TestHTTP404OutsideSecretPath(t *testing.T) {
	env := newTestEnv(t)
	for _, path := range []string{"/", "/login", "/status", env.cfg.WebPath + "evil", env.cfg.WebPath + "/../status", "/nexounel-panel"} {
		rec := env.do(http.MethodGet, path, nil, nil)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", path, rec.Code)
		}
		if rec.Body.String() != "404 page not found\n" {
			t.Fatalf("GET %s: body %q leaks information", path, rec.Body.String())
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatalf("GET %s: set a cookie", path)
		}
		for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
			if rec.Header().Get(h) == "" {
				t.Fatalf("GET %s: missing security header %s", path, h)
			}
		}
		if strings.Contains(rec.Body.String(), "Nexounel") || strings.Contains(rec.Header().Get("Server"), "Nexounel") {
			t.Fatalf("GET %s: panel-identifying leak", path)
		}
	}
}

func TestHTTPAuthRequiredOnEveryRoute(t *testing.T) {
	env := newTestEnv(t)
	paths := []string{"/status", "/connections", "/logs", "/wizard", "/nodes", "/jobs"}
	for _, p := range paths {
		rec := env.do(http.MethodGet, env.cfg.WebPath+p, nil, nil)
		if rec.Code != http.StatusFound || !strings.HasSuffix(rec.Header().Get("Location"), "/login") {
			t.Fatalf("GET %s without auth: status %d location %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	for _, p := range []string{"/logout", "/wizard", "/nodes/rotate", "/nodes/remove", "/restart-server"} {
		rec := env.do(http.MethodPost, env.cfg.WebPath+p, url.Values{}, nil)
		if rec.Code != http.StatusFound {
			t.Fatalf("POST %s without auth: status %d, want redirect to login", p, rec.Code)
		}
	}
}

func TestHTTPLoginSuccessCookieFlagsAndLockout(t *testing.T) {
	env := newTestEnv(t)
	cookie, _ := env.loginCookie(t)
	if !cookie.HttpOnly {
		t.Fatal("session cookie is not HttpOnly")
	}
	if cookie.Path != env.cfg.WebPath {
		t.Fatalf("session cookie path %q, want %q", cookie.Path, env.cfg.WebPath)
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie SameSite = %v", cookie.SameSite)
	}
	if cookie.Secure {
		t.Fatal("session cookie must not be Secure when tls_secure is false")
	}
	// Authenticated status page loads.
	rec := env.do(http.MethodGet, env.cfg.WebPath+"/status", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("status page status %d", rec.Code)
	}
	// Lockout: fresh env, 5 failures then a correct password is refused.
	env2 := newTestEnv(t)
	rec = env2.do(http.MethodGet, env2.cfg.WebPath+"/login", nil, nil)
	cookie2 := rec.Result().Cookies()[0]
	csrf := csrfPattern.FindStringSubmatch(rec.Body.String())[1]
	for i := 0; i < 5; i++ {
		rec = env2.do(http.MethodPost, env2.cfg.WebPath+"/login", url.Values{"username": {"admin"}, "password": {"wrong-password"}, "csrf_token": {csrf}}, cookie2)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("failure %d: status %d", i+1, rec.Code)
		}
	}
	rec = env2.do(http.MethodPost, env2.cfg.WebPath+"/login", url.Values{"username": {"admin"}, "password": {"example-password"}, "csrf_token": {csrf}}, cookie2)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "Too many failed") {
		t.Fatalf("locked-out login: status %d body %s", rec.Code, rec.Body.String())
	}
	// Logout invalidates server-side.
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/logout", url.Values{"csrf_token": {env.csrfFor(t, cookie, env.cfg.WebPath+"/status")}}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("logout status %d", rec.Code)
	}
	rec = env.do(http.MethodGet, env.cfg.WebPath+"/status", nil, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("logged-out session still authenticated: %d", rec.Code)
	}
}

func TestHTTPCSRFRejection(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.authed(t)
	// POST without any token.
	rec := env.do(http.MethodPost, env.cfg.WebPath+"/wizard", url.Values{"action": {"cancel"}}, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF: status %d", rec.Code)
	}
	// POST with a wrong token.
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/wizard", url.Values{"action": {"cancel"}, "csrf_token": {"bogus"}}, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST with wrong CSRF: status %d", rec.Code)
	}
	// Registry unchanged by the rejected requests.
	entries, err := ReadRegistryEntries(env.registry)
	if err != nil || len(entries) != 1 {
		t.Fatalf("registry changed by rejected POST: %+v err=%v", entries, err)
	}
}

func TestHTTPStatusAndLogsRedaction(t *testing.T) {
	env := newTestEnv(t)
	// Metrics endpoint up.
	metrics := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			_, _ = fmt.Fprint(w, "ok\n")
		case "/healthz/details":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"status":"ok","uptime_seconds":99,"monitoring":[{"name":"active_sessions","value":2,"type":"gauge","unit":"sessions"}],"transports":{"udp_up":true}}`)
		case "/metrics":
			_, _ = fmt.Fprint(w, "# TYPE x gauge\ncottendns_active_sessions 2\n")
		}
	}))
	defer metrics.Close()
	env.cfg.MetricsAddr = strings.TrimPrefix(metrics.URL, "http://")
	env.server.cfg.MetricsAddr = env.cfg.MetricsAddr
	cookie := env.authed(t)
	rec := env.do(http.MethodGet, env.cfg.WebPath+"/status", nil, cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "up") || !strings.Contains(body, "active_sessions") || !strings.Contains(body, "99") {
		t.Fatalf("status page missing health data: %d\n%s", rec.Code, body)
	}
	if strings.Contains(body, validTestKey(1)) {
		t.Fatal("status page leaked a registry key")
	}
	if !strings.Contains(body, "node-1") {
		t.Fatal("status page missing node id")
	}
	// Logs: planted secret must be dropped.
	rec = env.do(http.MethodGet, env.cfg.WebPath+"/logs", nil, cookie)
	body = rec.Body.String()
	if strings.Contains(body, "planted-secret-example") {
		t.Fatalf("log page rendered a secret line:\n%s", body)
	}
	if !strings.Contains(body, "plain line") {
		t.Fatalf("log page missing safe lines:\n%s", body)
	}
}

func TestHTTPWizardManualFlow(t *testing.T) {
	env := newTestEnv(t)
	cookie := env.authed(t)
	csrf := env.csrfFor(t, cookie, env.cfg.WebPath+"/wizard")
	form := url.Values{
		"action": {"verify-manual"}, "domain": {"example.invalid"}, "subdomain": {"v"},
		"mother_ip": {"203.0.113.10"}, "node_id": {"node-2"}, "listen_port": {"18000"},
		"forward_range": {"20000-20010"}, "csrf_token": {csrf},
	}
	rec := env.do(http.MethodPost, env.cfg.WebPath+"/wizard", form, cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "shown once") || !strings.Contains(body, "v.example.invalid") {
		t.Fatalf("wizard verify: status %d\n%s", rec.Code, body)
	}
	// Extract the shown key and confirm.
	m := regexp.MustCompile(`id="nodekey"[^>]*value="([0-9a-f]{32})"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("deliverables page did not show a node key:\n%s", body)
	}
	key := m[1]
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/wizard", url.Values{"action": {"confirm"}, "csrf_token": {csrf}}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Node registered") {
		t.Fatalf("wizard confirm: status %d\n%s", rec.Code, rec.Body.String())
	}
	reg, err := multisessionLoad(env.registry)
	if err != nil {
		t.Fatal(err)
	}
	node, ok := reg["node-2"]
	if !ok || node != key {
		t.Fatalf("registry after confirm: %+v", reg)
	}
	// The key is not shown again on a fresh wizard visit.
	rec = env.do(http.MethodGet, env.cfg.WebPath+"/wizard", nil, cookie)
	if strings.Contains(rec.Body.String(), key) {
		t.Fatal("node key shown again after confirmation")
	}
	// Validation errors: bad domain.
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/wizard", url.Values{
		"action": {"verify-manual"}, "domain": {"not a domain"}, "subdomain": {"v"},
		"mother_ip": {"203.0.113.10"}, "forward_range": {"20000-20010"}, "csrf_token": {csrf},
	}, cookie)
	if !strings.Contains(rec.Body.String(), "invalid domain") {
		t.Fatalf("wizard validation error missing:\n%s", rec.Body.String())
	}
}

func TestHTTPWizardAutoFlow(t *testing.T) {
	env := newTestEnv(t)
	cf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, `{"success":true,"result":[{"id":"zone-test-key-1","name":"example.invalid"}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"success":true,"result":{"id":"rec-test-key-1"}}`)
	}))
	defer cf.Close()
	env.server.cloudflareBase = cf.URL
	cookie := env.authed(t)
	csrf := env.csrfFor(t, cookie, env.cfg.WebPath+"/wizard")
	form := url.Values{
		"action": {"create-auto"}, "domain": {"example.invalid"}, "subdomain": {"v"},
		"mother_ip": {"203.0.113.10"}, "node_id": {"node-3"}, "listen_port": {"18000"},
		"forward_range": {"20000-20010"}, "cf_email": {"admin@example.invalid"},
		"cf_api_key": {"test-key-global"}, "csrf_token": {csrf},
	}
	rec := env.do(http.MethodPost, env.cfg.WebPath+"/wizard", form, cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "shown once") || !strings.Contains(body, "scoped API token") {
		t.Fatalf("wizard auto: status %d\n%s", rec.Code, body)
	}
	if strings.Contains(body, "test-key-global") {
		t.Fatal("wizard page echoed the Cloudflare authorization")
	}
	// Confirm registers the node.
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/wizard", url.Values{"action": {"confirm"}, "csrf_token": {csrf}}, cookie)
	if !strings.Contains(rec.Body.String(), "Node registered") {
		t.Fatalf("wizard auto confirm failed:\n%s", rec.Body.String())
	}
	// Token-style auth with a failing zone lookup: error, no pending.
	env2 := newTestEnv(t)
	failCF := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"success":false,"errors":[{"code":9109,"message":"invalid access"}]}`)
	}))
	defer failCF.Close()
	env2.server.cloudflareBase = failCF.URL
	cookie2 := env2.authed(t)
	csrf2 := env2.csrfFor(t, cookie2, env2.cfg.WebPath+"/wizard")
	rec = env2.do(http.MethodPost, env2.cfg.WebPath+"/wizard", url.Values{
		"action": {"create-auto"}, "domain": {"example.invalid"}, "subdomain": {"v"},
		"mother_ip": {"203.0.113.10"}, "forward_range": {"20000-20010"},
		"cf_api_token": {"test-key-token"}, "csrf_token": {csrf2},
	}, cookie2)
	if !strings.Contains(rec.Body.String(), "Could not find the Cloudflare zone") {
		t.Fatalf("wizard auto failure not reported:\n%s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), `id="nodekey"`) {
		t.Fatal("failed wizard run produced deliverables")
	}
}

func TestHTTPProvisionRotateRemoveAndRestart(t *testing.T) {
	env := newTestEnv(t)
	env.server.syncJobs = true
	cookie := env.authed(t)
	csrf := env.csrfFor(t, cookie, env.cfg.WebPath+"/nodes")

	// Provision node-1 with mock transports.
	first := &mockTransport{fingerprint: "SHA256:paneltestfp"}
	second := &mockTransport{fingerprint: "SHA256:paneltestfp"}
	env.factory = &mockFactory{transports: []*mockTransport{first, second}}
	rec := env.do(http.MethodPost, env.cfg.WebPath+"/nodes/provision", url.Values{
		"node_id": {"node-1"}, "ssh_host": {"203.0.113.50"}, "ssh_port": {"22"}, "ssh_user": {"root"},
		"ssh_password": {"example-password-12345"}, "listen_port": {"18000"},
		"forward_range": {"20000-20010"}, "connect_addr": {"v.example.invalid"}, "csrf_token": {csrf},
	}, cookie)
	if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "/jobs/") {
		t.Fatalf("provision redirect: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	jobPage := env.do(http.MethodGet, rec.Header().Get("Location"), nil, cookie)
	if !strings.Contains(jobPage.Body.String(), "succeeded") {
		t.Fatalf("provision job did not succeed:\n%s", jobPage.Body.String())
	}
	if strings.Contains(jobPage.Body.String(), "example-password-12345") || strings.Contains(jobPage.Body.String(), validTestKey(1)) {
		t.Fatal("job page leaked a secret")
	}

	// Rotate node-1: registry key changes and a delivery job succeeds.
	oldKey := validTestKey(1)
	first2 := &mockTransport{}
	second2 := &mockTransport{}
	env.factory = &mockFactory{transports: []*mockTransport{first2, second2}}
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/nodes/rotate", url.Values{
		"node_id": {"node-1"}, "ssh_host": {"203.0.113.50"}, "ssh_port": {"22"}, "ssh_user": {"root"},
		"ssh_password": {"example-password-12345"}, "csrf_token": {csrf},
	}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("rotate redirect: %d", rec.Code)
	}
	reg, err := multisessionLoad(env.registry)
	if err != nil {
		t.Fatal(err)
	}
	if reg["node-1"] == oldKey || reg["node-1"] == "" {
		t.Fatalf("rotation did not change the registry key: %+v", reg)
	}
	jobPage = env.do(http.MethodGet, rec.Header().Get("Location"), nil, cookie)
	if !strings.Contains(jobPage.Body.String(), "succeeded") {
		t.Fatalf("rotate job did not succeed:\n%s", jobPage.Body.String())
	}

	// Restart server (mock systemctl): banner clears after success.
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/restart-server", url.Values{"confirm": {"yes"}, "csrf_token": {csrf}}, cookie)
	if rec.Code != http.StatusFound {
		t.Fatalf("restart redirect: %d", rec.Code)
	}
	rec = env.do(http.MethodGet, env.cfg.WebPath+"/status", nil, cookie)
	if !strings.Contains(rec.Body.String(), "restarted and is active") {
		t.Fatalf("restart result missing:\n%s", rec.Body.String())
	}

	// Remove the only node: refused.
	rec = env.do(http.MethodPost, env.cfg.WebPath+"/nodes/remove", url.Values{
		"node_id": {"node-1"}, "confirm": {"yes"}, "csrf_token": {csrf},
	}, cookie)
	if !strings.Contains(rec.Body.String(), "last node") {
		t.Fatalf("removing last node not refused:\n%s", rec.Body.String())
	}
	entries, err := ReadRegistryEntries(env.registry)
	if err != nil || len(entries) != 1 {
		t.Fatalf("registry changed by refused removal: %+v", entries)
	}
}

func TestHTTPHostKeyConfirmationFlow(t *testing.T) {
	env := newTestEnv(t)
	env.server.syncJobs = true
	cookie := env.authed(t)
	csrf := env.csrfFor(t, cookie, env.cfg.WebPath+"/nodes")
	unconfirmed := &UnconfirmedHostKeyError{Fingerprint: "SHA256:newhostfp"}
	first := &mockTransport{dialErr: unconfirmed}
	env.factory = &mockFactory{transports: []*mockTransport{first}}
	rec := env.do(http.MethodPost, env.cfg.WebPath+"/nodes/provision", url.Values{
		"node_id": {"node-1"}, "ssh_host": {"203.0.113.50"}, "ssh_port": {"22"}, "ssh_user": {"root"},
		"ssh_password": {"example-password-12345"}, "listen_port": {"18000"},
		"forward_range": {"20000-20010"}, "connect_addr": {"v.example.invalid"}, "csrf_token": {csrf},
	}, cookie)
	jobURL := rec.Header().Get("Location")
	jobPage := env.do(http.MethodGet, jobURL, nil, cookie)
	if !strings.Contains(jobPage.Body.String(), "needs-confirmation") || !strings.Contains(jobPage.Body.String(), "SHA256:newhostfp") {
		t.Fatalf("TOFU job page wrong:\n%s", jobPage.Body.String())
	}
	// Confirm the fingerprint: it is persisted to the panel config.
	rec = env.do(http.MethodPost, jobURL+"/confirm-hostkey", url.Values{"confirm": {"yes"}, "csrf_token": {csrf}}, cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Fingerprint saved") {
		t.Fatalf("hostkey confirm: %d\n%s", rec.Code, rec.Body.String())
	}
	saved, err := LoadConfig(env.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.KnownHosts["203.0.113.50:22"] != "SHA256:newhostfp" {
		t.Fatalf("fingerprint not persisted: %+v", saved.KnownHosts)
	}
	if saved.Username != "admin" || saved.PasswordHash == "" {
		t.Fatal("fingerprint save clobbered admin credentials")
	}
}

func multisessionLoad(path string) (map[string]string, error) {
	entries, err := ReadRegistryEntries(path)
	if err != nil {
		return nil, err
	}
	// Resolve key_file entries the same way the server loader does.
	out := map[string]string{}
	for _, e := range entries {
		key := e.Key
		if key == "" && e.KeyFile != "" {
			data, err := os.ReadFile(e.KeyFile)
			if err != nil {
				return nil, err
			}
			key = strings.TrimSpace(string(data))
		}
		out[e.ID] = key
	}
	return out, nil
}

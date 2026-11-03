package panel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/logger"
)

// Server is the panel HTTP server. Everything it serves lives under the
// secret web path; any other path gets a generic 404.
type Server struct {
	cfg     Config
	cfgPath string
	log     *logger.Logger

	sessions *SessionStore
	limiter  *RateLimiter
	jobs     *JobStore

	pendingMu sync.Mutex
	pending   map[string]PendingNode

	restartMu     sync.Mutex
	restartNeeded bool
	restartResult string
	manualRestart string

	// Overridable seams for tests.
	dnsResolver    DNSResolver
	cloudflareBase string
	httpClient     *http.Client
	runner         CommandRunner
	factoryForAddr func(addr string) TransportFactory
	syncJobs       bool

	// Control-socket seams for tests. controlSocketPathOverride, when
	// non-nil, replaces the path resolved from the server config file
	// (an empty override forces "not configured"). controlClientFactory,
	// when set, builds the control client for a socket path (a fake
	// socket server in tests).
	controlSocketPathOverride *string
	controlClientFactory      func(socketPath string) controlClient
}

// NewServer builds a panel server from a loaded config.
func NewServer(cfg Config, cfgPath string, log *logger.Logger) *Server {
	if log == nil {
		log = logger.New("Nexounel Panel", "INFO")
	}
	return &Server{
		cfg: cfg, cfgPath: cfgPath, log: log,
		sessions: NewSessionStore(), limiter: NewRateLimiter(), jobs: NewJobStore(),
		pending:        map[string]PendingNode{},
		dnsResolver:    NewUDPResolver(),
		httpClient:     &http.Client{Timeout: 15 * time.Second},
		runner:         DefaultCommandRunner,
		factoryForAddr: func(addr string) TransportFactory { return NewRealTransportFactory(addr) },
	}
}

func (s *Server) setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
}

func (s *Server) generic404(w http.ResponseWriter, r *http.Request) {
	s.setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("404 page not found\n"))
}

// underWebPath reports whether path is the web path itself or below it.
func (s *Server) underWebPath(path string) bool {
	if path == s.cfg.WebPath || path == s.cfg.WebPath+"/" {
		return true
	}
	return strings.HasPrefix(path, s.cfg.WebPath+"/")
}

func (s *Server) subPath(path string) string {
	rest := strings.TrimPrefix(path, s.cfg.WebPath)
	if rest == "" {
		rest = "/"
	}
	return rest
}

// ServeHTTP routes every request. Security headers are set on all
// responses, including the generic 404 outside the secret path.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.setSecurityHeaders(w)
	if !s.underWebPath(r.URL.Path) {
		s.generic404(w, r)
		return
	}
	// The JSON agent API lives under the same secret path and the same
	// session authentication as the UI, but with JSON error semantics
	// (401/404 JSON, never a redirect). Unknown /api/* paths are 404
	// JSON without an auth check, matching the generic 404 outside
	// the secret path.
	if sub := s.subPath(r.URL.Path); sub == "/api" || strings.HasPrefix(sub, "/api/") {
		s.handleAPI(w, r)
		return
	}
	switch s.subPath(r.URL.Path) {
	case "/", "":
		s.requireAuth(http.HandlerFunc(s.handleRoot)).ServeHTTP(w, r)
	case "/login":
		s.handleLogin(w, r)
	case "/logout":
		s.requireAuth(http.HandlerFunc(s.handleLogout)).ServeHTTP(w, r)
	case "/status":
		s.requireAuth(http.HandlerFunc(s.handleStatus)).ServeHTTP(w, r)
	case "/restart-server":
		s.requireAuth(http.HandlerFunc(s.handleRestartServer)).ServeHTTP(w, r)
	case "/compression":
		s.requireAuth(http.HandlerFunc(s.handleCompressionSettings)).ServeHTTP(w, r)
	case "/registry/reload":
		s.requireAuth(http.HandlerFunc(s.handleRegistryReload)).ServeHTTP(w, r)
	case "/registry/add":
		s.requireAuth(http.HandlerFunc(s.handleRegistryAdd)).ServeHTTP(w, r)
	case "/registry/remove":
		s.requireAuth(http.HandlerFunc(s.handleRegistryRemove)).ServeHTTP(w, r)
	case "/registry/rotate":
		s.requireAuth(http.HandlerFunc(s.handleRegistryRotate)).ServeHTTP(w, r)
	case "/logs":
		s.requireAuth(http.HandlerFunc(s.handleLogs)).ServeHTTP(w, r)
	case "/wizard":
		s.requireAuth(http.HandlerFunc(s.handleWizard)).ServeHTTP(w, r)
	case "/nodes":
		s.requireAuth(http.HandlerFunc(s.handleNodes)).ServeHTTP(w, r)
	case "/nodes/provision":
		s.requireAuth(http.HandlerFunc(s.handleProvision)).ServeHTTP(w, r)
	case "/nodes/rotate":
		s.requireAuth(http.HandlerFunc(s.handleRotate)).ServeHTTP(w, r)
	case "/nodes/deliver":
		s.requireAuth(http.HandlerFunc(s.handleDeliver)).ServeHTTP(w, r)
	case "/nodes/remove":
		s.requireAuth(http.HandlerFunc(s.handleRemoveNode)).ServeHTTP(w, r)
	case "/jobs":
		s.requireAuth(http.HandlerFunc(s.handleJobs)).ServeHTTP(w, r)
	default:
		if strings.HasPrefix(s.subPath(r.URL.Path), "/jobs/") {
			s.requireAuth(http.HandlerFunc(s.handleJob)).ServeHTTP(w, r)
			return
		}
		s.generic404(w, r)
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, s.cfg.WebPath+"/status", http.StatusFound)
}

const sessionCookieName = "nexounel_panel_session"

func (s *Server) sessionFromRequest(r *http.Request) *Session {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}
	sess, ok := s.sessions.Get(cookie.Value)
	if !ok {
		return nil
	}
	return sess
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: token, Path: s.cfg.WebPath,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cfg.TLSSecure,
		MaxAge: 12 * 3600,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: s.cfg.WebPath,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: s.cfg.TLSSecure,
		MaxAge: -1,
	})
}

// requireAuth redirects unauthenticated requests to the login page and
// enforces CSRF on POSTs.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFromRequest(r)
		if sess == nil || !sess.Authenticated || sess.Username != s.cfg.Username {
			http.Redirect(w, r, s.cfg.WebPath+"/login", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				s.renderError(w, r, http.StatusBadRequest, "Could not read the submitted form.", sess)
				return
			}
			if !ValidCSRF(sess, r.FormValue("csrf_token")) {
				s.renderError(w, r, http.StatusForbidden, "Invalid or missing security token. Please try again.", sess)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) pageData(r *http.Request, sess *Session, title string) PageData {
	data := PageData{Title: title, WebPath: s.cfg.WebPath}
	if sess != nil {
		data.Authenticated = sess.Authenticated
		data.Username = sess.Username
		data.CSRFToken = sess.CSRFToken
	}
	return data
}

// handleLogin serves the login form and processes logins. A pre-auth
// session (created on GET) carries the login form's CSRF token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sess := s.sessionFromRequest(r)
		if sess != nil && sess.Authenticated {
			http.Redirect(w, r, s.cfg.WebPath+"/status", http.StatusFound)
			return
		}
		if sess == nil {
			created, err := s.sessions.Create()
			if err != nil {
				s.renderError(w, r, http.StatusInternalServerError, "Could not start a login session.", nil)
				return
			}
			sess = created
			s.setSessionCookie(w, sess.Token)
		}
		s.render(w, r, "login", s.pageData(r, sess, "Log in"))
	case http.MethodPost:
		sess := s.sessionFromRequest(r)
		if sess == nil {
			http.Redirect(w, r, s.cfg.WebPath+"/login", http.StatusFound)
			return
		}
		if err := r.ParseForm(); err != nil {
			s.renderError(w, r, http.StatusBadRequest, "Could not read the submitted form.", sess)
			return
		}
		if !ValidCSRF(sess, r.FormValue("csrf_token")) {
			data := s.pageData(r, sess, "Log in")
			data.Error = "Invalid or missing security token. Please try again."
			w.WriteHeader(http.StatusForbidden)
			s.render(w, r, "login", data)
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		ip := clientIP(r)
		if s.limiter.Locked(ip, username) {
			data := s.pageData(r, sess, "Log in")
			data.Error = "Too many failed login attempts. Try again in a few minutes."
			w.WriteHeader(http.StatusTooManyRequests)
			s.render(w, r, "login", data)
			return
		}
		ok, err := VerifyPassword(s.cfg.PasswordHash, password)
		if err != nil || !ok || username != s.cfg.Username {
			s.limiter.RecordFailure(ip, username)
			data := s.pageData(r, sess, "Log in")
			data.Error = "Invalid username or password."
			w.WriteHeader(http.StatusUnauthorized)
			s.render(w, r, "login", data)
			return
		}
		s.limiter.RecordSuccess(ip, username)
		newToken, err := s.sessions.Authenticate(sess.Token, username)
		if err != nil {
			s.renderError(w, r, http.StatusInternalServerError, "Could not start a login session.", nil)
			return
		}
		s.setSessionCookie(w, newToken)
		http.Redirect(w, r, s.cfg.WebPath+"/status", http.StatusFound)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.Invalidate(cookie.Value)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, s.cfg.WebPath+"/login", http.StatusFound)
}

type statusContent struct {
	Health        ServerHealth
	Nodes         []RegistryNodeView
	RegistryError string
	Resolver      ResolverHealth
	RestartNeeded bool
	RestartResult string
	ManualRestart string

	// Dashboard sections, loaded by the shared service layer (see
	// service.go) and rendered by the dashboard template. The JSON
	// API serialises the same values.
	Control      ControlSocketState
	Sessions     []SessionView
	SessionsNote string
	Compression  CompressionStatus
	ConfigFiles  ConfigFileState

	// ShownKey carries a freshly generated node key for exactly one
	// render (add/rotate with a generated key). It is never stored
	// server-side beyond the registry write. ShownNodeID names the
	// node it belongs to; ShownFingerprint is its key fingerprint.
	ShownKey         string
	ShownNodeID      string
	ShownFingerprint string
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	sess := s.sessionFromRequest(r)
	content := s.loadDashboard(r.Context())
	s.restartMu.Lock()
	content.RestartResult, content.ManualRestart = s.restartResult, s.manualRestart
	s.restartResult, s.manualRestart = "", ""
	s.restartMu.Unlock()
	data := s.pageData(r, sess, "Dashboard")
	data.Content = content
	s.render(w, r, "status", data)
}

// renderDashboard renders the dashboard with caller-supplied content
// plus an optional error or message banner (used by the dashboard
// POST handlers, which re-render instead of redirecting so a
// shown-once key survives exactly one render).
func (s *Server) renderDashboard(w http.ResponseWriter, r *http.Request, sess *Session, content statusContent, errMsg, message string) {
	data := s.pageData(r, sess, "Dashboard")
	data.Error = errMsg
	data.Message = message
	data.Content = content
	s.render(w, r, "status", data)
}

// handleRestartServer is the admin-confirmed "Apply & restart server"
// button. If systemctl is unavailable (the panel is not on the mother),
// it shows the manual command instead of failing silently.
func (s *Server) handleRestartServer(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if r.FormValue("confirm") != "yes" {
		data := s.pageData(r, sess, "Dashboard")
		data.Error = "Restart requires confirmation."
		s.render(w, r, "status", dataWithContent(data, s.statusContentFor(r)))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	_, err := s.runner(ctx, "systemctl", "restart", "nexounel")
	s.restartMu.Lock()
	defer s.restartMu.Unlock()
	if err != nil {
		if strings.Contains(err.Error(), "executable file not found") || strings.Contains(err.Error(), "no such file") {
			s.manualRestart = "systemctl restart nexounel"
			s.restartResult = ""
		} else {
			s.restartResult = fmt.Sprintf("Server restart failed: %s. Run this on the mother server: systemctl restart nexounel", err.Error())
		}
		http.Redirect(w, r, s.cfg.WebPath+"/status", http.StatusFound)
		return
	}
	activeOut, err := s.runner(ctx, "systemctl", "is-active", "nexounel")
	if err != nil || strings.TrimSpace(activeOut) != "active" {
		s.restartResult = "Server restart was requested but the service is not active afterwards. Check the service on the mother server."
	} else {
		s.restartResult = "Server restarted and is active."
		s.restartNeeded = false
	}
	http.Redirect(w, r, s.cfg.WebPath+"/status", http.StatusFound)
}

func (s *Server) statusContentFor(r *http.Request) statusContent {
	return s.loadDashboard(r.Context())
}

type logsContent struct {
	Tails LogTails
	Lines int
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	sess := s.sessionFromRequest(r)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tails := TailServiceLogs(ctx, s.cfg.LogTailLines, s.runner)
	data := s.pageData(r, sess, "Logs")
	data.Content = logsContent{Tails: tails, Lines: s.cfg.LogTailLines}
	s.render(w, r, "logs", data)
}

func (s *Server) markRestartNeeded() {
	s.restartMu.Lock()
	s.restartNeeded = true
	s.restartMu.Unlock()
}

package panel

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/sys/unix"
)

// Argon2id parameters for the admin password hash.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB (64 MiB)
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword hashes a password into a PHC-format argon2id string:
// $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

type argonParams struct {
	memory, time, threads uint32
	salt, hash            []byte
}

func parseArgon2idPHC(encoded string) (*argonParams, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, errors.New("not an argon2id v19 PHC string")
	}
	p := &argonParams{}
	var m, t, th int
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, fmt.Errorf("malformed argon2id parameter %q", kv)
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("malformed argon2id parameter %q", kv)
		}
		switch k {
		case "m":
			m = n
		case "t":
			t = n
		case "p":
			th = n
		default:
			return nil, fmt.Errorf("unknown argon2id parameter %q", k)
		}
	}
	if m == 0 || t == 0 || th == 0 {
		return nil, errors.New("argon2id parameters m, t and p are all required")
	}
	p.memory, p.time, p.threads = uint32(m), uint32(t), uint32(th)
	var err error
	if p.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return nil, fmt.Errorf("decode argon2id salt: %w", err)
	}
	if p.hash, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return nil, fmt.Errorf("decode argon2id hash: %w", err)
	}
	if len(p.salt) == 0 || len(p.hash) == 0 {
		return nil, errors.New("argon2id salt and hash must not be empty")
	}
	return p, nil
}

// VerifyPassword checks a password against a PHC argon2id hash using a
// constant-time comparison of the derived key.
func VerifyPassword(encodedHash, password string) (bool, error) {
	p, err := parseArgon2idPHC(encodedHash)
	if err != nil {
		return false, err
	}
	derived := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, uint8(p.threads), uint32(len(p.hash)))
	if len(derived) != len(p.hash) {
		return false, nil
	}
	return subtle.ConstantTimeCompare(derived, p.hash) == 1, nil
}

// Session is one server-side login session.
type Session struct {
	Token         string
	Username      string
	Authenticated bool
	CSRFToken     string
	LastSeen      time.Time
}

const sessionIdleTimeout = 12 * time.Hour

// SessionStore is the in-memory server-side session store.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	now      func() time.Time
}

// NewSessionStore creates an empty session store.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: map[string]*Session{}, now: time.Now}
}

func randomTokenHex(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Create mints a new, unauthenticated session (used to carry the login
// form's CSRF token) and returns it.
func (s *SessionStore) Create() (*Session, error) {
	token, err := randomTokenHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate session token: %w", err)
	}
	csrf, err := randomTokenHex(32)
	if err != nil {
		return nil, fmt.Errorf("generate CSRF token: %w", err)
	}
	sess := &Session{Token: token, CSRFToken: csrf, LastSeen: s.now()}
	s.mu.Lock()
	s.sessions[token] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get returns a live session, refreshing its idle timer. Expired sessions
// are removed and reported as absent.
func (s *SessionStore) Get(token string) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	if s.now().Sub(sess.LastSeen) > sessionIdleTimeout {
		delete(s.sessions, token)
		return nil, false
	}
	sess.LastSeen = s.now()
	return sess, true
}

// Authenticate marks a pre-auth session authenticated and rotates its
// token (defeating session fixation). It returns the new token.
func (s *SessionStore) Authenticate(oldToken, username string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[oldToken]
	if !ok {
		return "", errors.New("session not found")
	}
	newToken, err := randomTokenHex(32)
	if err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	delete(s.sessions, oldToken)
	sess.Token = newToken
	sess.Username = username
	sess.Authenticated = true
	sess.LastSeen = s.now()
	s.sessions[newToken] = sess
	return newToken, nil
}

// Invalidate removes a session server-side (logout).
func (s *SessionStore) Invalidate(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// ValidCSRF reports whether token matches the session's CSRF token using
// a constant-time comparison.
func ValidCSRF(sess *Session, token string) bool {
	if sess == nil {
		return false
	}
	a := []byte(sess.CSRFToken)
	b := []byte(token)
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RateLimiter enforces 5 failed logins -> 5-minute lockout per
// (source IP + username).
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempts
	now      func() time.Time
}

type loginAttempts struct {
	failures    int
	lockedUntil time.Time
}

const (
	maxLoginFailures = 5
	loginLockout     = 5 * time.Minute
)

// NewRateLimiter creates an empty login rate limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{attempts: map[string]*loginAttempts{}, now: time.Now}
}

func rateLimitKey(ip, username string) string { return ip + "\x00" + username }

// Locked reports whether the (ip, username) pair is currently locked out.
func (r *RateLimiter) Locked(ip, username string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.attempts[rateLimitKey(ip, username)]
	return ok && r.now().Before(a.lockedUntil)
}

// RecordFailure counts a failed login; the 5th failure locks the pair.
func (r *RateLimiter) RecordFailure(ip, username string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := rateLimitKey(ip, username)
	a, ok := r.attempts[key]
	if !ok {
		a = &loginAttempts{}
		r.attempts[key] = a
	}
	if r.now().Before(a.lockedUntil) {
		return
	}
	a.failures++
	if a.failures >= maxLoginFailures {
		a.lockedUntil = r.now().Add(loginLockout)
		a.failures = 0
	}
}

// RecordSuccess clears the failure history for the (ip, username) pair.
func (r *RateLimiter) RecordSuccess(ip, username string) {
	r.mu.Lock()
	delete(r.attempts, rateLimitKey(ip, username))
	r.mu.Unlock()
}

// ReadPassword prompts on /dev/tty and reads a line with echo disabled.
// When no TTY is available it falls back to reading from stdin and prints
// a warning that the input will be visible.
func ReadPassword(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: no terminal available; password input will be visible")
		fmt.Fprint(os.Stderr, prompt)
		reader := bufio.NewReader(os.Stdin)
		line, readErr := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), readErr
	}
	defer func() { _ = tty.Close() }()
	fd := int(tty.Fd())
	oldState, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return "", fmt.Errorf("read terminal state: %w", err)
	}
	newState := *oldState
	newState.Lflag &^= unix.ECHO
	newState.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &newState); err != nil {
		return "", fmt.Errorf("disable terminal echo: %w", err)
	}
	defer func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, oldState) }()
	if _, err := fmt.Fprint(tty, prompt); err != nil {
		return "", err
	}
	reader := bufio.NewReader(tty)
	line, err := reader.ReadString('\n')
	_, _ = fmt.Fprint(tty, "\n")
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MNSH-Nexo/Nexounel/core/internal/config"
	"github.com/MNSH-Nexo/Nexounel/core/internal/multisession"
	"github.com/MNSH-Nexo/Nexounel/core/internal/security"
)

// Metric is one monitoring entry from the server health details payload.
// Only the fields the panel displays are parsed.
type Metric struct {
	Name  string `json:"name"`
	Value uint64 `json:"value"`
	Type  string `json:"type"`
	Unit  string `json:"unit,omitempty"`
}

// HealthTransports mirrors the transports block of /healthz/details.
type HealthTransports struct {
	UDPEnabled     bool `json:"udp_enabled"`
	UDPUp          bool `json:"udp_up"`
	TCPEnabled     bool `json:"tcp_enabled"`
	TCPUp          bool `json:"tcp_up"`
	DoTEnabled     bool `json:"dot_enabled"`
	DoTUp          bool `json:"dot_up"`
	DoHEnabled     bool `json:"doh_enabled"`
	DoHUp          bool `json:"doh_up"`
	ExternalSOCKS5 bool `json:"external_socks5"`
}

// HealthDetails is the defensive subset of /healthz/details the panel shows.
type HealthDetails struct {
	Status        string           `json:"status"`
	Version       string           `json:"version"`
	UptimeSeconds uint64           `json:"uptime_seconds"`
	Transports    HealthTransports `json:"transports"`
	Warnings      []string         `json:"warnings"`
	Monitoring    []Metric         `json:"monitoring"`
}

// ServerHealth is the panel's view of the mother server.
type ServerHealth struct {
	Up                bool
	Details           *HealthDetails
	MetricsAvailable  bool
	MetricsValueCount int
	Error             string
}

// FetchServerHealth scrapes the metrics address with a 3s timeout per
// request. A failed liveness check marks the server down; a failed
// details or metrics fetch leaves those parts unavailable rather than
// fabricating values.
func FetchServerHealth(ctx context.Context, metricsAddr string, client *http.Client) ServerHealth {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	base := "http://" + metricsAddr
	health := ServerHealth{}
	liveCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(liveCtx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		health.Error = err.Error()
		return health
	}
	resp, err := client.Do(req)
	if err != nil {
		health.Error = err.Error()
		return health
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		health.Error = fmt.Sprintf("health endpoint returned status %d", resp.StatusCode)
		return health
	}
	health.Up = true

	detailCtx, cancelDetail := context.WithTimeout(ctx, 3*time.Second)
	defer cancelDetail()
	detailReq, err := http.NewRequestWithContext(detailCtx, http.MethodGet, base+"/healthz/details", nil)
	if err == nil {
		detailReq.Header.Set("Accept", "application/json")
		if detailResp, err := client.Do(detailReq); err == nil {
			defer func() { _ = detailResp.Body.Close() }()
			if detailResp.StatusCode == http.StatusOK {
				var details HealthDetails
				if err := json.NewDecoder(detailResp.Body).Decode(&details); err == nil {
					health.Details = &details
				}
			}
		}
	}

	metricsCtx, cancelMetrics := context.WithTimeout(ctx, 3*time.Second)
	defer cancelMetrics()
	metricsReq, err := http.NewRequestWithContext(metricsCtx, http.MethodGet, base+"/metrics", nil)
	if err == nil {
		if metricsResp, err := client.Do(metricsReq); err == nil {
			defer func() { _ = metricsResp.Body.Close() }()
			if metricsResp.StatusCode == http.StatusOK {
				health.MetricsAvailable = true
				// Count value lines without retaining the body: the panel
				// only reports that metrics exist and how many series
				// were served.
				buf := make([]byte, 32*1024)
				leftover := ""
				for {
					n, readErr := metricsResp.Body.Read(buf)
					if n > 0 {
						chunk := leftover + string(buf[:n])
						lines := strings.Split(chunk, "\n")
						leftover = lines[len(lines)-1]
						for _, line := range lines[:len(lines)-1] {
							line = strings.TrimSpace(line)
							if line != "" && !strings.HasPrefix(line, "#") {
								health.MetricsValueCount++
							}
						}
					}
					if readErr != nil {
						break
					}
				}
				if leftover = strings.TrimSpace(leftover); leftover != "" && !strings.HasPrefix(leftover, "#") {
					health.MetricsValueCount++
				}
			}
		}
	}
	return health
}

// RegistryNodeView is one registry entry for display: id plus the key
// fingerprint only. Keys are never exposed.
type RegistryNodeView struct {
	ID          string
	Fingerprint string
}

// ListRegistryNodes reads the registry through multisession.LoadRegistry
// (which resolves key_file entries) and returns id + fingerprint views.
func ListRegistryNodes(registryPath string) ([]RegistryNodeView, error) {
	reg, err := multisession.LoadRegistry(registryPath)
	if err != nil {
		return nil, err
	}
	views := make([]RegistryNodeView, 0, len(reg.Nodes))
	for _, node := range reg.Nodes {
		views = append(views, RegistryNodeView{ID: node.ID, Fingerprint: security.KeyFingerprint(node.Key)})
	}
	return views, nil
}

// ResolverEntry is one resolver measurement parsed from a resolver cache log.
type ResolverEntry struct {
	IP          string
	Port        int
	Domain      string
	UploadMTU   int
	DownloadMTU int
	LastSeen    time.Time
}

// ResolverClass groups resolvers that share a download MTU operating point.
type ResolverClass struct {
	DownloadMTU int
	UploadMTU   int // smallest upload MTU in the class
	Count       int
}

// ResolverHealth is the best-effort node resolver view.
type ResolverHealth struct {
	Available  bool
	SourceFile string
	Entries    []ResolverEntry
	Classes    []ResolverClass
	Note       string
}

// LoadNodeResolverHealth reads the node client config (when present) and
// parses the newest resolver_cache_*.log under its log directory. Every
// failure mode reports unavailable rather than inventing numbers.
func LoadNodeResolverHealth(nodeConfigPath string) ResolverHealth {
	cfg, err := config.LoadClientConfig(nodeConfigPath)
	if err != nil {
		return ResolverHealth{Note: "node config unavailable"}
	}
	logDir := cfg.ResolvedLogDir()
	pattern := filepath.Join(logDir, "resolver_cache_*.log")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		return ResolverHealth{Note: "no resolver cache log found"}
	}
	newest := ""
	var newestMod time.Time
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest, newestMod = file, info.ModTime()
		}
	}
	if newest == "" {
		return ResolverHealth{Note: "no resolver cache log found"}
	}
	entries := ParseResolverCacheLog(newest)
	if len(entries) == 0 {
		return ResolverHealth{SourceFile: newest, Note: "resolver cache log has no usable entries"}
	}
	return ResolverHealth{Available: true, SourceFile: newest, Entries: entries, Classes: groupResolverClasses(entries)}
}

// ParseResolverCacheLog parses one resolver cache log defensively. Lines
// follow "<RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>"; malformed lines
// are skipped.
func ParseResolverCacheLog(path string) []ResolverEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entries []ResolverEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, ok := parseResolverCacheLine(line)
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].DownloadMTU != entries[j].DownloadMTU {
			return entries[i].DownloadMTU > entries[j].DownloadMTU
		}
		return entries[i].IP < entries[j].IP
	})
	return entries
}

func parseResolverCacheLine(line string) (ResolverEntry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return ResolverEntry{}, false
	}
	ts, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return ResolverEntry{}, false
	}
	host, portStr, err := net.SplitHostPort(fields[1])
	if err != nil {
		return ResolverEntry{}, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return ResolverEntry{}, false
	}
	up, err := parseCacheKV(fields[3], "UP")
	if err != nil || up <= 0 {
		return ResolverEntry{}, false
	}
	down, err := parseCacheKV(fields[4], "DOWN")
	if err != nil || down <= 0 {
		return ResolverEntry{}, false
	}
	return ResolverEntry{IP: host, Port: port, Domain: fields[2], UploadMTU: up, DownloadMTU: down, LastSeen: ts}, true
}

func parseCacheKV(field, key string) (int, error) {
	prefix := key + "="
	if !strings.HasPrefix(field, prefix) {
		return 0, fmt.Errorf("expected %s= prefix", key)
	}
	return strconv.Atoi(field[len(prefix):])
}

func groupResolverClasses(entries []ResolverEntry) []ResolverClass {
	byMTU := map[int]*ResolverClass{}
	for _, e := range entries {
		class, ok := byMTU[e.DownloadMTU]
		if !ok {
			class = &ResolverClass{DownloadMTU: e.DownloadMTU, UploadMTU: e.UploadMTU}
			byMTU[e.DownloadMTU] = class
		}
		class.Count++
		if e.UploadMTU < class.UploadMTU {
			class.UploadMTU = e.UploadMTU
		}
	}
	classes := make([]ResolverClass, 0, len(byMTU))
	for _, class := range byMTU {
		classes = append(classes, *class)
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].DownloadMTU > classes[j].DownloadMTU })
	return classes
}

// CommandRunner runs a local command and returns combined stdout.
type CommandRunner func(ctx context.Context, name string, args ...string) (string, error)

// DefaultCommandRunner runs the command with the caller's context.
func DefaultCommandRunner(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// LogTails holds the bounded, redacted tails of both service units.
type LogTails struct {
	ServerLines []string
	NodeLines   []string
	ServerOK    bool
	NodeOK      bool
}

// TailServiceLogs runs journalctl for both units (best-effort) and drops
// any line that may carry secret material. When journalctl is missing
// or a unit has no entries, that tail is reported unavailable.
func TailServiceLogs(ctx context.Context, lines int, runner CommandRunner) LogTails {
	if runner == nil {
		runner = DefaultCommandRunner
	}
	if lines <= 0 {
		lines = 100
	}
	tails := LogTails{}
	serverOut, err := runner(ctx, "journalctl", "-u", "nexounel", "--no-pager", "-n", strconv.Itoa(lines))
	if err == nil {
		tails.ServerOK = true
		tails.ServerLines = RedactLogLines(splitLogLines(serverOut))
	}
	nodeOut, err := runner(ctx, "journalctl", "-u", "nexounel-node", "--no-pager", "-n", strconv.Itoa(lines))
	if err == nil {
		tails.NodeOK = true
		tails.NodeLines = RedactLogLines(splitLogLines(nodeOut))
	}
	return tails
}

func splitLogLines(out string) []string {
	lines := strings.Split(out, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		kept = append(kept, line)
	}
	return kept
}

// RunLocalCommand runs a local command with a timeout and returns stdout.
// It is used for admin-confirmed local service control (server restart).
func RunLocalCommand(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return DefaultCommandRunner(ctx, name, args...)
}

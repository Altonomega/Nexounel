// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
// Package client provides the core logic for the CottenDns client.
// This file (resolver_cache_log.go) handles per-session resolver cache logging.
// Each line records a working resolver together with its MTU values so that
// future runs can start quickly by skipping the full MTU scan.
//
// Line format:
//
//	<RFC3339>  <ip:port>  <domain>  UP=<n>  DOWN=<n>  UPLOSS=<permille>  DOWNLOSS=<permille>
//
// Example:
//
//	2026-04-20T15:04:05Z  8.8.8.8:53  v.domain.com  UP=64  DOWN=120  UPLOSS=0  DOWNLOSS=50
//
// The UPLOSS/DOWNLOSS tokens are optional; older logs without them still parse.
// ==============================================================================
package client

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	// resolverCacheLogRetainCount bounds how many resolver_cache_*.log
	// files are kept per log directory.
	resolverCacheLogRetainCount = 7
	// resolverCacheLogRetainRecent is the grace period during which a
	// cache log file is never pruned, however many siblings exist. It
	// protects files that concurrently starting sessions (for example
	// the probe client and the class sessions) just created.
	resolverCacheLogRetainRecent = 24 * time.Hour
)

// pruneResolverCacheLogs deletes resolver_cache_*.log siblings in dir
// beyond the newest resolverCacheLogRetainCount, except files modified
// within resolverCacheLogRetainRecent and the just-opened keepPath.
// Best-effort and silent: rotation must never fail startup or spam logs.
func pruneResolverCacheLogs(dir, keepPath string) {
	if dir == "" {
		return
	}
	files, err := filepath.Glob(filepath.Join(dir, "resolver_cache_*.log"))
	if err != nil || len(files) <= resolverCacheLogRetainCount {
		return
	}
	type logFile struct {
		path string
		mod  time.Time
	}
	infos := make([]logFile, 0, len(files))
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		infos = append(infos, logFile{path: file, mod: info.ModTime()})
	}
	if len(infos) <= resolverCacheLogRetainCount {
		return
	}
	sort.Slice(infos, func(i, j int) bool {
		if !infos[i].mod.Equal(infos[j].mod) {
			return infos[i].mod.After(infos[j].mod)
		}
		return infos[i].path > infos[j].path
	})
	now := time.Now()
	for i, info := range infos {
		if i < resolverCacheLogRetainCount {
			continue
		}
		if info.path == keepPath {
			continue
		}
		if now.Sub(info.mod) < resolverCacheLogRetainRecent {
			continue
		}
		_ = os.Remove(info.path)
	}
}

// openResolverCacheLog creates (or truncates) the resolver cache log file for
// this session. The parent directory is created if it does not exist. When path
// is empty or any I/O error occurs the feature is silently disabled.
func (c *Client) openResolverCacheLog(path string) {
	if c == nil || path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		if c.mtuWarnEnabled() {
			c.log.Warnf(
				"<yellow>[Cache]</yellow> Failed to create log directory for resolver cache: %v",
				err,
			)
		}
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		if c.mtuWarnEnabled() {
			c.log.Warnf(
				"<yellow>[Cache]</yellow> Failed to open resolver cache log %s: %v",
				path,
				err,
			)
		}
		return
	}

	c.resolverCacheLogMu.Lock()
	c.resolverCacheLogFile = f
	c.resolverCacheLogMu.Unlock()

	// Scale-audit fix F2: one file per session accumulates without bound.
	// Prune siblings best-effort: keep the newest few, and never delete a
	// file modified within the last day, so files a concurrently starting
	// session just created are never removed from under it.
	pruneResolverCacheLogs(filepath.Dir(path), path)

	if c.mtuInfoEnabled() {
		c.log.Infof(
			"<blue>[Cache]</blue> Resolver cache log: <cyan>%s</cyan>",
			path,
		)
	}
}

// appendResolverCacheEntry writes one line to the resolver cache log for a
// connection that has been confirmed working (MTU values are positive).
// Format: <RFC3339> <ip:port> <domain> UP=<n> DOWN=<n>
func (c *Client) appendResolverCacheEntry(conn *Connection) {
	if c == nil || conn == nil || conn.UploadMTUBytes <= 0 || conn.DownloadMTUBytes <= 0 {
		return
	}

	c.resolverCacheLogMu.Lock()
	f := c.resolverCacheLogFile
	c.resolverCacheLogMu.Unlock()
	if f == nil {
		return
	}

	endpoint := formatResolverEndpoint(conn.Resolver, conn.ResolverPort)
	line := fmt.Sprintf(
		"%s %s %s UP=%d DOWN=%d UPLOSS=%d DOWNLOSS=%d\n",
		time.Now().UTC().Format(time.RFC3339),
		endpoint,
		conn.Domain,
		conn.UploadMTUBytes,
		conn.DownloadMTUBytes,
		int(conn.UploadMTULoss*1000+0.5),
		int(conn.DownloadMTULoss*1000+0.5),
	)

	c.resolverCacheLogMu.Lock()
	defer c.resolverCacheLogMu.Unlock()
	if c.resolverCacheLogFile != nil {
		_, _ = c.resolverCacheLogFile.WriteString(line)
	}
}

// Close releases resources held by a client that never entered
// Run: today, the resolver cache log file. It is safe to call
// more than once and on a client whose Run loop owns the log
// (the log close is mutex-guarded and idempotent). Long-running
// Run clients should not call Close while serving; enroll-mode
// attempts, which never call Run, close after every attempt so a
// retry loop cannot leak a file descriptor per attempt.
func (c *Client) Close() {
	c.closeResolverCacheLog()
}

// closeResolverCacheLog flushes and closes the cache log file.
func (c *Client) closeResolverCacheLog() {
	if c == nil {
		return
	}
	c.resolverCacheLogMu.Lock()
	defer c.resolverCacheLogMu.Unlock()
	if c.resolverCacheLogFile != nil {
		_ = c.resolverCacheLogFile.Close()
		c.resolverCacheLogFile = nil
	}
}

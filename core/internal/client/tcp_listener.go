// ==============================================================================
// CottenDNS
// Author: tajirax
// Github: https://github.com/TaJirax/CottenDns
// Year: 2026
// ==============================================================================
package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Altonomega/Nexounel/core/internal/netutil"
)

type TCPListener struct {
	client       *Client
	protocolType string
	listeners    []net.Listener
	stopChan     chan struct{}
	stopOnce     sync.Once
}

func NewTCPListener(c *Client, protocolType string) *TCPListener {
	return &TCPListener{
		client:       c,
		protocolType: protocolType,
		stopChan:     make(chan struct{}),
	}
}

func (l *TCPListener) Start(ctx context.Context, ip string, port int) error {
	addrs := listenerAddressesForBind(ip, port)
	if len(addrs) == 0 {
		return fmt.Errorf("invalid listener address")
	}

	listeners := make([]net.Listener, 0, len(addrs))
	for i, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			if i == 0 {
				for _, opened := range listeners {
					_ = opened.Close()
				}
				return err
			}
			if l.client != nil && l.client.log != nil {
				l.client.log.Debugf("Skipping optional listener bind on %s: %v", addr, err)
			}
			continue
		}
		listeners = append(listeners, listener)
	}

	if len(listeners) == 0 {
		return fmt.Errorf("failed to bind any proxy listener")
	}

	l.listeners = listeners
	for _, listener := range listeners {
		if l.client != nil && l.client.log != nil {
			l.client.log.Infof("🚀 <green>%s Proxy server is listening on <cyan>%s</cyan></green>", l.protocolType, listener.Addr().String())
		}

		go l.serveListener(ctx, listener)
	}

	l.logListenHint(ip, port, listeners)
	return nil
}

// StartRange binds one listener per port in [lo, hi] on the same bind IP
// and serves them all with the shared accept loop. It is used for
// TCP-forward port ranges (FORWARD_RANGE): the accepted connection's
// local port is the requested forward port (see HandleTCPConnect).
// Ports that fail to bind are skipped with a debug log; binding none
// at all is an error.
func (l *TCPListener) StartRange(ctx context.Context, ip string, lo, hi int) error {
	if lo < 1 || hi > 65535 || hi < lo {
		return fmt.Errorf("invalid listener port range %d-%d", lo, hi)
	}
	var listeners []net.Listener
	for port := lo; port <= hi; port++ {
		for _, addr := range listenerAddressesForBind(ip, port) {
			listener, err := net.Listen("tcp", addr)
			if err != nil {
				if l.client != nil && l.client.log != nil {
					l.client.log.Debugf("Skipping listener bind on %s: %v", addr, err)
				}
				continue
			}
			listeners = append(listeners, listener)
		}
	}
	if len(listeners) == 0 {
		return fmt.Errorf("failed to bind any proxy listener in range %d-%d", lo, hi)
	}
	l.listeners = listeners
	for _, listener := range listeners {
		if l.client != nil && l.client.log != nil {
			l.client.log.Infof("🚀 <green>%s Proxy server is listening on <cyan>%s</cyan></green>", l.protocolType, listener.Addr().String())
		}
		go l.serveListener(ctx, listener)
	}
	l.logListenHint(ip, lo, listeners)
	return nil
}

// serveListener is the shared accept loop for one bound listener.
func (l *TCPListener) serveListener(ctx context.Context, activeListener net.Listener) {
	for {
		conn, err := activeListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-l.stopChan:
				return
			case <-ctx.Done():
				return
			default:
				if listenerShouldRetryAccept(err) {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if l.client != nil && l.client.log != nil {
					l.client.log.Debugf("⚠️ <yellow>%s listener stopped after accept error: %v</yellow>", l.protocolType, err)
				}
				return
			}
		}
		go l.handleConnection(ctx, conn, l.protocolType)
	}
}

func (l *TCPListener) logListenHint(ip string, port int, listeners []net.Listener) {
	if l.client == nil || l.client.log == nil {
		return
	}
	actualPort := port
	if len(listeners) > 0 {
		if localAddr, ok := listeners[0].Addr().(*net.TCPAddr); ok && localAddr != nil && localAddr.Port > 0 {
			actualPort = localAddr.Port
		}
	}
	if hint := netutil.FormatListenHint(ip, actualPort); hint != "" {
		l.client.log.Infof("🌐 <green>%s Proxy %s</green>", l.protocolType, hint)
	}
}

func (l *TCPListener) Stop() {
	if l == nil {
		return
	}
	l.stopOnce.Do(func() {
		close(l.stopChan)
		for _, listener := range l.listeners {
			if listener != nil {
				_ = listener.Close()
			}
		}
		l.listeners = nil
	})
}

func listenerAddressesForBind(ip string, port int) []string {
	trimmed := strings.TrimSpace(ip)
	if trimmed == "" {
		return nil
	}

	build := func(host string) string {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}

	switch strings.ToLower(trimmed) {
	case "127.0.0.1", "::1", "localhost":
		// Local-only listener: try both loopback stacks so apps that resolve
		// localhost to ::1 can still reach the proxy on platforms like macOS.
		return []string{build("127.0.0.1"), build("::1")}
	default:
		return []string{build(trimmed)}
	}
}

func listenerShouldRetryAccept(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
		type temporary interface {
			Temporary() bool
		}
		if tempErr, ok := any(netErr).(temporary); ok && tempErr.Temporary() {
			return true
		}
	}
	return false
}

// handleConnection manages the local proxy/TCP forwarding handshake and requests.
func (l *TCPListener) handleConnection(ctx context.Context, conn net.Conn, protocolType string) {
	switch protocolType {
	case "SOCKS5":
		l.client.HandleSOCKS5(ctx, conn)
	case "HTTP":
		l.client.HandleHTTPProxy(ctx, conn)
	default:
		l.client.HandleTCPConnect(ctx, conn)
	}
}

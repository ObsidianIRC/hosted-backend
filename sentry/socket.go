package sentry

import (
	"backend/sentry/events"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SocketServer accepts ONE active sentinel.c connection at a time
// over a local Unix socket. Each line is one JSON-encoded Event,
// fed into the Manager.
//
// Local-only by design: the socket lives at a filesystem path, not
// a TCP port. Permissions on the parent directory restrict access
// to the owning user.
type SocketServer struct {
	Path    string
	Manager *Manager
	Logger  *log.Logger // optional; defaults to log.Default()

	mu       sync.Mutex
	ln       net.Listener
	conn     net.Conn
	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewSocketServer creates the server but does not yet listen. Call
// Run to start accepting.
func NewSocketServer(path string, m *Manager) *SocketServer {
	return &SocketServer{
		Path:    path,
		Manager: m,
		Logger:  log.Default(),
		stopCh:  make(chan struct{}),
	}
}

// Listen creates the Unix socket, removing any stale leftover. Caller
// is responsible for ensuring the parent dir exists and has
// appropriate permissions.
func (s *SocketServer) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return fmt.Errorf("mkdir socket dir: %w", err)
	}
	// Stale socket from a prior run is harmless to remove.
	_ = os.Remove(s.Path)
	ln, err := net.Listen("unix", s.Path)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Path, err)
	}
	// Tight permissions: only the owning uid can connect.
	if err := os.Chmod(s.Path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod %s: %w", s.Path, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	s.Logger.Printf("[sentry/bridge] listening on unix:%s", s.Path)
	return nil
}

// Run blocks until ctx is cancelled or Stop is called. It maintains
// a single inbound sentinel connection -- if sentinel reconnects, the
// old conn is closed.
func (s *SocketServer) Run(ctx context.Context) error {
	if s.ln == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}

	// Goroutine to close listener on context done.
	go func() {
		select {
		case <-ctx.Done():
		case <-s.stopCh:
		}
		s.mu.Lock()
		if s.ln != nil {
			_ = s.ln.Close()
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.mu.Unlock()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.Logger.Printf("[sentry/bridge] accept error: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.mu.Lock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.conn = conn
		s.mu.Unlock()
		s.Logger.Printf("[sentry/bridge] accepted")
		go s.readLoop(conn)
	}
}

// Stop closes the listener and any active conn. Safe to call once.
func (s *SocketServer) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// readLoop consumes newline-delimited JSON events. Each event is
// dispatched to the Manager. Malformed lines are logged and skipped
// -- one bad event must not kill the stream.
func (s *SocketServer) readLoop(conn net.Conn) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	// Up to 256 KB per line: protects against runaway payloads while
	// leaving room for legitimate long chanmsg events.
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	parseErrors := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev events.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			parseErrors++
			if parseErrors <= 5 || parseErrors%100 == 0 {
				s.Logger.Printf("[sentry/bridge] bad event line (#%d): %v", parseErrors, err)
			}
			continue
		}
		if ev.Time == 0 {
			ev.Time = time.Now().UnixMilli()
		}
		s.Manager.Observe(&ev)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		s.Logger.Printf("[sentry/bridge] read error: %v", err)
	}
	s.mu.Lock()
	if s.conn == conn {
		s.conn = nil
	}
	s.mu.Unlock()
	s.Logger.Printf("[sentry/bridge] connection closed")
}

// IngestReader is the test/simulator entry point: hand it any reader
// of newline-delimited JSON events and it pumps them into the
// manager. Same logic as readLoop but without the network plumbing.
func IngestReader(r io.Reader, m *Manager, logger *log.Logger) error {
	if logger == nil {
		logger = log.Default()
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 256*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev events.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			logger.Printf("[sentry/ingest] bad event line: %v", err)
			continue
		}
		if ev.Time == 0 {
			ev.Time = time.Now().UnixMilli()
		}
		m.Observe(&ev)
	}
	return scanner.Err()
}

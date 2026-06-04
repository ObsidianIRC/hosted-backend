// Package adminapi exposes a tiny HTTP control surface for opers.
// Bound to localhost only -- the bot (hosted-backend main) calls it
// to drive /sentry-* commands.
//
// Endpoints:
//
//   GET  /v1/stats               -- counters, model state, recent alerts
//   GET  /v1/explain?nick=<n>    -- explainability report for a live user
//   POST /v1/label               -- {nick,verdict,evidence,source}
//                                   verdict in {bad,good,ignore}
//   GET  /v1/recent-alerts?limit=N
//
// No authentication: relies on the listener binding to 127.0.0.1.
// Anyone with shell access on the host can already poke obbyircd
// directly, so this is the same trust level.
package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"backend/sentry/explain"
	"backend/sentry/feedback"
	"backend/sentry/heuristics"
)

type Server struct {
	Addr    string // typically "127.0.0.1:9601"
	Manager Manager

	srv *http.Server

	mu          sync.RWMutex
	recent      []heuristics.Alert
	recentCap   int
}

// Manager is the slice of *sentry.Manager we depend on. Kept as an
// interface so tests can stub it without spinning a full Manager
// and so the adminapi package doesn't import sentry (which would
// pull every layer through).
type Manager interface {
	Explain(uid string) explain.UserReport
	RecordFeedback(l feedback.Label) (int64, error)
	UIDByNick(nick string) string
	Stats() ManagerStats
}

// ManagerStats mirrors sentry.ManagerStats so the api package
// doesn't have to import sentry (which would create a cycle through
// the cmd/sentry binary).
type ManagerStats struct {
	TrackedUsers int      `json:"tracked_users"`
	EventsTotal  int64    `json:"events_total"`
	AlertsTotal  int64    `json:"alerts_total"`
	RuleNames    []string `json:"rule_names"`
}

func New(addr string, m Manager) *Server {
	return &Server{Addr: addr, Manager: m, recentCap: 200}
}

// Close on the RPCSink calls (*unrealircd.Connection).Close which
// doesn't exist; lib relies on GC. We keep a no-op Close so other
// callers can hold a Closer.
var _ Manager = (Manager)(nil)

// RememberAlerts is meant to be installed as the AlertSink chain so
// the admin API can show recent alerts. Composes with the regular
// log/Orca sink -- the daemon installs both.
func (s *Server) RememberAlerts(alerts []heuristics.Alert) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recent = append(s.recent, alerts...)
	if len(s.recent) > s.recentCap {
		s.recent = s.recent[len(s.recent)-s.recentCap:]
	}
}

func (s *Server) Emit(alerts []heuristics.Alert) { s.RememberAlerts(alerts) }

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/stats", s.handleStats)
	mux.HandleFunc("/v1/explain", s.handleExplain)
	mux.HandleFunc("/v1/label", s.handleLabel)
	mux.HandleFunc("/v1/recent-alerts", s.handleRecentAlerts)

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Addr, err)
	}
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()
	log.Printf("[admin-api] listening on %s", s.Addr)
	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[admin-api] serve error: %v", err)
		}
	}()
	return nil
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Manager.Stats())
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	nick := r.URL.Query().Get("nick")
	uid := r.URL.Query().Get("uid")
	if uid == "" && nick == "" {
		http.Error(w, "nick or uid required", http.StatusBadRequest)
		return
	}
	if uid == "" {
		uid = s.Manager.UIDByNick(nick)
		if uid == "" {
			http.Error(w, "no user with that nick", http.StatusNotFound)
			return
		}
	}
	writeJSON(w, http.StatusOK, s.Manager.Explain(uid))
}

func (s *Server) handleLabel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Nick      string `json:"nick"`
		UID       string `json:"uid"`
		Verdict   string `json:"verdict"`
		Evidence  string `json:"evidence"`
		Source    string `json:"source"`
		AlertKind string `json:"alert_kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	uid := in.UID
	if uid == "" {
		uid = s.Manager.UIDByNick(in.Nick)
		if uid == "" {
			http.Error(w, "no user with that nick", http.StatusNotFound)
			return
		}
	}
	var v feedback.Verdict
	switch in.Verdict {
	case "bad":
		v = feedback.VerdictBad
	case "good":
		v = feedback.VerdictGood
	case "ignore":
		v = feedback.VerdictIgnore
	default:
		http.Error(w, "verdict must be bad|good|ignore", http.StatusBadRequest)
		return
	}
	id, err := s.Manager.RecordFeedback(feedback.Label{
		UID: uid, Nick: in.Nick, Verdict: v,
		Source: in.Source, Evidence: in.Evidence, AlertKind: in.AlertKind,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "verdict": v.String()})
}

func (s *Server) handleRecentAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.recent
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("[admin-api] encode: %v", err)
	}
}

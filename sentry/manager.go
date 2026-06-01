package sentry

import (
	"backend/sentry/events"
	"context"
	"log"
	"sync"
	"time"

	"backend/sentry/heuristics"
)

// AlertSink is anything that wants to receive alerts. The bot/Orca
// integration plugs in here -- when L1+L2+L3 consensus fires the sink
// gets a slice of alerts so it can post to #opers or take action.
//
// Implementations MUST be non-blocking (return fast) or accept that
// detection latency will suffer.
type AlertSink interface {
	Emit(alerts []heuristics.Alert)
}

// nopSink discards alerts. Useful for tests + the simulator.
type nopSink struct{}

func (nopSink) Emit([]heuristics.Alert) {}

// Manager is the top-level sentry coordinator. It owns the per-user
// state map, the L1 rule registry, and an alert sink (Orca etc).
// Future L2/L3 layers will be wired in here as additional steps in
// the dispatch path.
type Manager struct {
	mu sync.RWMutex

	// Users keyed by UID (stable across nick changes); also indexed
	// by current nick for fast nick -> uid lookup.
	users   map[string]*userState
	byNick  map[string]string

	rules *heuristics.Registry
	sink  AlertSink

	// Periodic stats / cleanup.
	gcInterval time.Duration
	maxIdle    time.Duration

	stopOnce sync.Once
	stopCh   chan struct{}

	// Stats.
	eventCount  int64
	alertCount  int64
}

type ManagerOption func(*Manager)

func WithSink(s AlertSink) ManagerOption {
	return func(m *Manager) { m.sink = s }
}

func WithRules(r *heuristics.Registry) ManagerOption {
	return func(m *Manager) { m.rules = r }
}

func WithMaxIdle(d time.Duration) ManagerOption {
	return func(m *Manager) { m.maxIdle = d }
}

func NewManager(opts ...ManagerOption) *Manager {
	m := &Manager{
		users:      map[string]*userState{},
		byNick:     map[string]string{},
		rules:      heuristics.DefaultRegistry(),
		sink:       nopSink{},
		gcInterval: 30 * time.Second,
		maxIdle:    2 * time.Hour,
		stopCh:     make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Run starts the background GC. Returns when ctx is cancelled or
// Stop is called.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(m.gcInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-t.C:
			m.gc()
		}
	}
}

func (m *Manager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
}

// Observe ingests one event. This is the single entry point that the
// sentinel-socket reader (and the simulator) calls. Hot path: must
// stay fast.
func (m *Manager) Observe(ev *events.Event) {
	if ev == nil {
		return
	}
	m.eventCount++

	// Routing by event kind. Connect/register create/update user;
	// quit removes; activity events update aggregates.
	switch ev.Kind {
	case events.EventConnect, events.EventRegister:
		m.upsertUser(ev)
		return // connect by itself isn't actionable
	case events.EventQuit:
		m.removeUser(ev)
		return
	case events.EventNick:
		m.handleNick(ev)
	}

	u := m.getOrCreate(ev)
	if u == nil {
		return
	}

	// Update sliding-window state per event kind.
	switch ev.Kind {
	case events.EventChanMsg, events.EventUserMsg, events.EventChanNotice:
		u.onMessage(ev)
	case events.EventJoin:
		u.onJoin(ev)
	case events.EventPart, events.EventKick:
		u.onPart(ev)
	case events.EventCTCP:
		u.onCTCP(ev)
	}

	// Build the snapshot the L1 rules see. Do this OUTSIDE the per-
	// user lock by reading snapshotted values.
	snap := m.snapshotFor(u, ev.At())
	alerts := m.rules.Dispatch(snap, ev)
	if len(alerts) > 0 {
		m.alertCount += int64(len(alerts))
		m.sink.Emit(alerts)
	}
}

// upsertUser creates or updates a user's identity bookkeeping on
// connect/register events.
func (m *Manager) upsertUser(ev *events.Event) {
	if ev.UID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[ev.UID]
	if !ok {
		u = &userState{
			UID:       ev.UID,
			FirstSeen: ev.At(),
		}
		m.users[ev.UID] = u
	}
	u.mu.Lock()
	if ev.Nick != "" {
		u.Nick = ev.Nick
		m.byNick[ev.Nick] = ev.UID
	}
	if ev.Ident != "" {
		u.Ident = ev.Ident
	}
	if ev.Host != "" {
		u.Host = ev.Host
	}
	if ev.IP != "" {
		// Parse but don't error out -- net.ParseIP is nil-safe to print.
		u.IP = parseIPSafe(ev.IP)
	}
	if ev.Account != "" {
		u.Account = ev.Account
	}
	u.IsTLS = ev.IsTLS
	u.LastActivity = ev.At()
	u.mu.Unlock()
}

func (m *Manager) removeUser(ev *events.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	uid := ev.UID
	if uid == "" && ev.Nick != "" {
		uid = m.byNick[ev.Nick]
	}
	if uid == "" {
		return
	}
	if u, ok := m.users[uid]; ok {
		delete(m.byNick, u.Nick)
		delete(m.users, uid)
	}
}

func (m *Manager) handleNick(ev *events.Event) {
	if ev.UID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[ev.UID]
	if !ok {
		return
	}
	u.mu.Lock()
	old := u.Nick
	if ev.TargetNick != "" {
		u.Nick = ev.TargetNick
	} else if ev.Nick != "" && ev.Nick != old {
		u.Nick = ev.Nick
	}
	newNick := u.Nick
	u.NickCount++
	u.LastActivity = ev.At()
	u.mu.Unlock()
	delete(m.byNick, old)
	m.byNick[newNick] = ev.UID
}

// getOrCreate locates the user for the event. Creates a minimal
// record if none exists -- protects against events arriving before
// sentinel sends connect (e.g. on sentry warm-start mid-session).
func (m *Manager) getOrCreate(ev *events.Event) *userState {
	if ev.UID != "" {
		m.mu.RLock()
		if u, ok := m.users[ev.UID]; ok {
			m.mu.RUnlock()
			return u
		}
		m.mu.RUnlock()
	}
	if ev.Nick != "" {
		m.mu.RLock()
		if uid, ok := m.byNick[ev.Nick]; ok {
			u := m.users[uid]
			m.mu.RUnlock()
			return u
		}
		m.mu.RUnlock()
	}
	if ev.UID == "" && ev.Nick == "" {
		return nil
	}
	m.upsertUser(ev)
	m.mu.RLock()
	defer m.mu.RUnlock()
	if ev.UID != "" {
		return m.users[ev.UID]
	}
	return m.users[m.byNick[ev.Nick]]
}

// snapshotFor builds the heuristics.userSnapshot the rules see.
// Read-only on the userState.
func (m *Manager) snapshotFor(u *userState, now time.Time) heuristics.UserSnapshot {
	fv := u.snapshotFeatures(now)
	u.mu.RLock()
	defer u.mu.RUnlock()
	dupHits := 0
	for _, c := range u.msgHashes {
		if c > 1 {
			dupHits += c - 1
		}
	}
	return heuristics.UserSnapshot{
		UID:            u.UID,
		Nick:           u.Nick,
		FirstSeen:      u.FirstSeen,
		IsTLS:          u.IsTLS,
		HasAccount:     u.Account != "" && u.Account != "*",
		MsgCount:       u.MsgCount,
		JoinCount:      u.JoinCount,
		CTCPCount:      u.CTCPCount,
		LastMsgAt:      u.LastMsg,
		RecentMsgRate:  fv.MsgRatePerMin,
		RecentJoinRate: fv.JoinRatePerMin,
		DupHashCount:   dupHits,
		URLCount:       int(fv.URLCount),
		UpperRatioMean: fv.UpperRatioMean,
	}
}

// gc walks the user table and evicts records that have been idle
// past maxIdle. Bounded memory under long-running sessions.
func (m *Manager) gc() {
	cutoff := time.Now().Add(-m.maxIdle)
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, u := range m.users {
		u.mu.RLock()
		stale := u.LastActivity.Before(cutoff)
		nick := u.Nick
		u.mu.RUnlock()
		if stale {
			delete(m.users, uid)
			delete(m.byNick, nick)
		}
	}
}

// Stats returns a cheap snapshot of the manager's totals. Used for
// the Orca explainability tools.
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return ManagerStats{
		TrackedUsers: len(m.users),
		EventsTotal:  m.eventCount,
		AlertsTotal:  m.alertCount,
		RuleNames:    m.rules.Names(),
	}
}

type ManagerStats struct {
	TrackedUsers int
	EventsTotal  int64
	AlertsTotal  int64
	RuleNames    []string
}

// LogSink is a simple AlertSink that just log.Printfs each alert.
// Used during development and by the simulator harness.
type LogSink struct{}

func (LogSink) Emit(alerts []heuristics.Alert) {
	for _, a := range alerts {
		log.Printf("[sentry/alert] %s nick=%q ch=%q conf=%.2f -- %s",
			a.Kind, a.Nick, a.Channel, a.Confidence, a.Evidence)
	}
}

// parseIPSafe is a panic-free wrapper around net.ParseIP for use in
// hot paths. Local helper to avoid importing net here.
func parseIPSafe(s string) []byte {
	if ip := parseIPv4(s); ip != nil {
		return ip
	}
	return nil
}

func parseIPv4(s string) []byte {
	// Lightweight: only "a.b.c.d". Real IPv6 / IPv4-mapped go through
	// userState.IP being nil, which is fine for v0 (the heuristics
	// here don't read it yet).
	dots := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			dots++
		}
	}
	if dots != 3 {
		return nil
	}
	out := make([]byte, 4)
	n, v := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if v > 255 {
				return nil
			}
			out[n] = byte(v)
			n++
			v = 0
		} else if c >= '0' && c <= '9' {
			v = v*10 + int(c-'0')
		} else {
			return nil
		}
	}
	if v > 255 {
		return nil
	}
	out[3] = byte(v)
	return out
}

package sentry

import (
	"context"
	"log"
	"math"
	"strconv"
	"sync"
	"time"

	"backend/sentry/anomaly"
	"backend/sentry/classifier"
	"backend/sentry/events"
	"backend/sentry/explain"
	"backend/sentry/feedback"
	"backend/sentry/heuristics"
)

// AlertSink receives alerts emitted by the training pipeline. Must
// be non-blocking on Emit.
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

	// L2: anomaly baseline. Optional -- if nil, L2 is disabled and
	// only L1 alerts fire. When set, every event's feature vector is
	// scored against the baseline; deviations above the model's
	// ZThreshold yield anomaly:<feature> alerts.
	anomalyModel *anomaly.Model
	// anomalyTrainOnly: when true, L2 ONLY trains (no scoring).
	// Used while pre-warming the baseline with known-benign data.
	anomalyTrainOnly bool

	// L3: online logistic regression classifier. Optional. When set,
	// every feature-bearing event gets a malice probability; above
	// classifierThreshold an "ml" alert fires. The classifier eats
	// L1 alert flags as stacked features so it can learn that L1
	// hits reinforce other suspicious signals.
	classifier          *classifier.Model
	classifierThreshold float64 // probability above which we emit ml alert

	feedback *feedback.Store

	// classifierLabeler returns (label, hasLabel) for a UID. Used by
	// the simulator to feed labeled scenarios into SGD.
	classifierLabeler func(uid string) (float64, bool)

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

// WithAnomalyModel turns L2 on. The model is shared across all users
// and updated/scored on every event whose user has at least one
// message of state.
func WithAnomalyModel(am *anomaly.Model) ManagerOption {
	return func(m *Manager) { m.anomalyModel = am }
}

// WithAnomalyTrainOnly keeps L2 in training mode: feature vectors are
// folded into the baseline but scores are not produced. Toggle off
// after pre-training to enable detection.
func WithAnomalyTrainOnly(yes bool) ManagerOption {
	return func(m *Manager) { m.anomalyTrainOnly = yes }
}

// AnomalyModel returns the current model (or nil). Callers can flip
// training/scoring modes at runtime via SetAnomalyTrainOnly.
func (m *Manager) AnomalyModel() *anomaly.Model { return m.anomalyModel }

// SetAnomalyTrainOnly toggles training-only mode at runtime.
func (m *Manager) SetAnomalyTrainOnly(yes bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.anomalyTrainOnly = yes
}

// WithClassifier turns L3 on with the given probability threshold.
// A threshold of 0.8 means "fire ml alert when the model is at least
// 80% sure this user is malicious".
func WithClassifier(c *classifier.Model, threshold float64) ManagerOption {
	return func(m *Manager) {
		m.classifier = c
		m.classifierThreshold = threshold
	}
}

// WithClassifierLabeler installs a function that supplies the
// ground-truth label for a UID. Used by the simulator; nil in
// production (operator labels arrive via RecordFeedback instead).
func WithClassifierLabeler(fn func(uid string) (float64, bool)) ManagerOption {
	return func(m *Manager) { m.classifierLabeler = fn }
}

// Classifier returns the active L3 model (or nil). Used for
// explainability and persistence.
func (m *Manager) Classifier() *classifier.Model { return m.classifier }

// UIDByNick looks up the server-assigned UID for a current nick.
// Returns "" if no user with that nick is currently tracked.
func (m *Manager) UIDByNick(nick string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byNick[nick]
}

// WithFeedbackStore wires the operator-feedback SQLite store. When
// present, RecordFeedback persists labels AND triggers an L3 SGD
// step using the user's current feature snapshot.
func WithFeedbackStore(s *feedback.Store) ManagerOption {
	return func(m *Manager) { m.feedback = s }
}

// RecordFeedback persists an operator-supplied verdict and, when
// decisive (Bad/Good), trains the L3 classifier with the user's
// current feature vector. The user's state must exist; an unknown
// UID returns ErrUnknownUser.
func (m *Manager) RecordFeedback(label feedback.Label) (int64, error) {
	if m.feedback == nil {
		return 0, ErrFeedbackDisabled
	}
	id, err := m.feedback.Record(label)
	if err != nil {
		return 0, err
	}
	if m.classifier == nil ||
		(label.Verdict != feedback.VerdictBad && label.Verdict != feedback.VerdictGood) {
		return id, nil
	}
	m.mu.RLock()
	u := m.users[label.UID]
	m.mu.RUnlock()
	if u == nil {
		return id, nil
	}
	fv := featuresToMap(u.snapshotFeatures(time.Now()))
	stacked := stackL1Features(fv, nil)
	target := 0.0
	if label.Verdict == feedback.VerdictBad {
		target = 1.0
	}
	m.classifier.Train(stacked, target)
	return id, nil
}

// Explain returns a UserReport for the given UID, with the user's
// current feature snapshot scored against the active L2 and L3
// models. Returns the zero report (no error) when the UID is unknown
// so callers can simply check Nick=="".
func (m *Manager) Explain(uid string) explain.UserReport {
	m.mu.RLock()
	u := m.users[uid]
	m.mu.RUnlock()
	if u == nil {
		return explain.UserReport{}
	}
	fv := featuresToMap(u.snapshotFeatures(time.Now()))
	stacked := stackL1Features(fv, nil)
	return explain.Explain(uid, u.Nick, stacked, m.classifier, m.anomalyModel)
}

// ErrFeedbackDisabled is returned by RecordFeedback when no feedback
// store has been wired.
var ErrFeedbackDisabled = sentryError("feedback store not configured")

type sentryError string

func (e sentryError) Error() string { return string(e) }

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
	case events.EventNick:
		u.onNick(ev)
	}

	// Build the snapshot the L1 rules see. Do this OUTSIDE the per-
	// user lock by reading snapshotted values.
	snap := m.snapshotFor(u, ev.At())
	alerts := m.rules.Dispatch(snap, ev)

	// L2: anomaly scoring. Only run when a message-bearing event
	// actually updated the feature vector -- joins/parts add little
	// to the distribution and would dilute the baseline.
	var fm anomaly.FeatureMap
	if (m.anomalyModel != nil || m.classifier != nil) && isFeatureBearing(ev.Kind) {
		fm = featuresToMap(u.snapshotFeatures(ev.At()))
	}
	if m.anomalyModel != nil && fm != nil {
		// Train on this sample UNLESS L1 already flagged the user --
		// L1 alerts are our cheapest "this user is probably bad"
		// signal, so excluding them keeps the baseline clean of the
		// most obvious malicious patterns.
		if len(alerts) == 0 {
			m.anomalyModel.Observe(fm)
		}
		if !m.anomalyTrainOnly {
			for _, f := range m.anomalyModel.Anomalous(fm) {
				alerts = append(alerts, heuristics.Alert{
					Kind:       "anomaly:" + string(f.Feature),
					UID:        u.UID,
					Nick:       u.Nick,
					Confidence: confidenceFromZ(f.Z),
					Evidence:   "z=" + floatStr(f.Z),
					At:         ev.At(),
				})
			}
		}
	}

	// L3: logistic regression. Stacks L1 alert flags onto the numeric
	// feature map so the classifier sees both "what numbers look like"
	// and "what the heuristics said". Train if a labeler is installed
	// (simulator path); always score; emit ml alert above threshold.
	//
	// Training-time gating: for malicious labels (>0.5), only train
	// AFTER L1 has fired at least once on this user. Without that
	// gate, the classifier sees benign-looking feature vectors (a
	// flood-spammer's first message before the burst is established)
	// labeled malicious -- which teaches "small msg_rate = bad" and
	// floods benign users with false positives at inference time.
	if m.classifier != nil && fm != nil {
		stacked := stackL1Features(fm, alerts)
		if m.classifierLabeler != nil {
			if label, ok := m.classifierLabeler(u.UID); ok {
				train := true
				if label > 0.5 {
					// Malicious label: require L1 evidence (either
					// fired this event, or fired previously and
					// stamped firstL1At on the user).
					if len(alerts) == 0 && u.FirstL1At.IsZero() {
						train = false
					}
				}
				if train {
					m.classifier.Train(stacked, label)
				}
			}
		}
		// Bookkeeping: mark the moment L1 first flagged this user.
		// The lock is fine here because we hold no other user lock.
		if len(alerts) > 0 {
			u.mu.Lock()
			if u.FirstL1At.IsZero() {
				u.FirstL1At = ev.At()
			}
			u.mu.Unlock()
		}
		p := m.classifier.Score(stacked)
		if p >= m.classifierThreshold {
			alerts = append(alerts, heuristics.Alert{
				Kind:       "ml",
				UID:        u.UID,
				Nick:       u.Nick,
				Confidence: p,
				Evidence:   "p=" + floatStr(p),
				At:         ev.At(),
			})
		}
	}

	if len(alerts) > 0 {
		m.alertCount += int64(len(alerts))
		m.sink.Emit(alerts)
	}

}

// stackL1Features builds the L3 input feature map. Numeric features
// are log-scaled via log(1+x) so SGD weight magnitudes stay sane
// regardless of how varied raw feature values are (msg_rate spans 0
// to ~80, url_count 0 to a handful). L1 alert flags are stacked in
// raw [0, 1] form -- they're already O(1) and represent rule votes.
//
// L2 ("anomaly:*") and L3 ("ml") alert kinds are excluded so the
// classifier can't peek at its own or L2's outputs while learning.
func stackL1Features(fm anomaly.FeatureMap, alerts []heuristics.Alert) anomaly.FeatureMap {
	out := make(anomaly.FeatureMap, len(fm)+len(alerts))
	for k, v := range fm {
		out[k] = math.Log1p(v)
	}
	for _, a := range alerts {
		if a.Kind == "ml" || hasPrefix(a.Kind, "anomaly:") {
			continue
		}
		out[anomaly.FeatureName(classifier.L1FeaturePrefix+a.Kind)] = a.Confidence
	}
	return out
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// isFeatureBearing reports whether the event kind meaningfully changes
// the feature vector -- i.e. should contribute to L2 training/scoring.
func isFeatureBearing(k events.EventKind) bool {
	switch k {
	case events.EventChanMsg, events.EventUserMsg, events.EventChanNotice,
		events.EventCTCP, events.EventJoin, events.EventPart, events.EventNick:
		return true
	}
	return false
}

// featuresToMap maps the positional FeatureVector to the named
// FeatureMap the anomaly model consumes.
func featuresToMap(fv FeatureVector) anomaly.FeatureMap {
	return anomaly.FeatureMap{
		anomaly.FeatMsgRate:        fv.MsgRatePerMin,
		anomaly.FeatJoinRate:       fv.JoinRatePerMin,
		anomaly.FeatMsgLenMean:     fv.MsgLenMean,
		anomaly.FeatMsgLenVar:      fv.MsgLenVar,
		anomaly.FeatDistinctHashes: fv.DistinctHashes,
		anomaly.FeatUniqueChannels: fv.UniqueChannels,
		anomaly.FeatUpperRatio:     fv.UpperRatioMean,
		anomaly.FeatURLCount:       fv.URLCount,
		anomaly.FeatCTCPCount:      fv.CTCPCount,
		anomaly.FeatIdleBurst:      fv.IdleBurstScore,
		anomaly.FeatNickFlipRate:   fv.NickFlipRate,
		anomaly.FeatHopRate:        fv.HopRate,
	}
}

// confidenceFromZ squashes |z| into [0, 1]: z=3 -> ~0.63, z=6 -> ~0.86.
func confidenceFromZ(z float64) float64 {
	if z < 0 {
		z = -z
	}
	return 1.0 - math.Exp(-z/3.0)
}

func floatStr(v float64) string {
	return strconv.FormatFloat(v, 'f', 2, 64)
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
	// No-op on QUIT: keeping the user's state lets opers run
	// /sentry-explain after the offender has left. The background GC
	// reaps records idle past maxIdle (default 2h). If a new user
	// grabs the same nick before then, upsertUser overwrites the
	// byNick entry for that nick to point at the new UID; the old
	// UID's record stays under its own key and ages out naturally.
	_ = ev
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
		DupHashCount:      dupHits,
		URLCount:          int(fv.URLCount),
		UpperRatioMean:    fv.UpperRatioMean,
		BurstStartIdleGap: u.burstStartIdleGap,
		NickFlipRate:      rateOverWindow(u.recentNicks, now, time.Minute),
		HopRate:           rateOverWindow(u.recentHops, now, time.Minute),
		PMRate:            pmRateOverWindow(u.recentUserMsg, now, time.Minute),
		PMTargetCount:     pmTargetCount(u.recentUserMsg, now, time.Minute),
		MentionRate:       rateOverWindow(u.recentMentions, now, time.Minute),
		NickServSpoofs:    pmSpoofCount(u.recentUserMsg, now, time.Minute),
	}
}

func pmRateOverWindow(rs []userMsgRecord, now time.Time, window time.Duration) float64 {
	if len(rs) == 0 {
		return 0
	}
	cutoff := now.Add(-window)
	n := 0
	for _, r := range rs {
		if !r.At.Before(cutoff) {
			n++
		}
	}
	return float64(n) / window.Minutes()
}

func pmTargetCount(rs []userMsgRecord, now time.Time, window time.Duration) int {
	if len(rs) == 0 {
		return 0
	}
	cutoff := now.Add(-window)
	seen := map[string]bool{}
	for _, r := range rs {
		if !r.At.Before(cutoff) && r.Target != "" {
			seen[r.Target] = true
		}
	}
	return len(seen)
}

func pmSpoofCount(rs []userMsgRecord, now time.Time, window time.Duration) int {
	if len(rs) == 0 {
		return 0
	}
	cutoff := now.Add(-window)
	n := 0
	for _, r := range rs {
		if !r.At.Before(cutoff) && hasNickServSpoof(r.Text) {
			n++
		}
	}
	return n
}

// rateOverWindow returns the per-minute rate of events in ts that
// fall within [now-window, now]. window is the duration we measure
// over; the return value is normalised to events/minute regardless.
func rateOverWindow(ts []time.Time, now time.Time, window time.Duration) float64 {
	if len(ts) == 0 || window <= 0 {
		return 0
	}
	cutoff := now.Add(-window)
	count := 0
	for _, t := range ts {
		if !t.Before(cutoff) {
			count++
		}
	}
	return float64(count) / window.Minutes()
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

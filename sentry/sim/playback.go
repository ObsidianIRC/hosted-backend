package sim

import (
	"math/rand"
	"sort"
	"sync"

	"backend/sentry/events"
	"backend/sentry/heuristics"
)

// Result is the per-scenario score after playing it through sentry.
type Result struct {
	Scenario Scenario
	Alerts   []heuristics.Alert // every alert the pipeline raised for this UID

	// Detected is true if the pipeline raised an alert whose Kind
	// matches the scenario's expected Label. For benign scenarios,
	// Detected is true iff NO alerts fired.
	Detected bool
}

// Manager is the abstract bit of the sentry runtime we need: anything
// with Observe(*events.Event). The real *sentry.Manager satisfies this.
type Manager interface {
	Observe(*events.Event)
}

// captureSink is the sink the harness installs in the Manager so we
// can attribute alerts to scenarios after the fact.
type captureSink struct {
	mu     sync.Mutex
	alerts []heuristics.Alert
}

func (c *captureSink) Emit(a []heuristics.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, a...)
}

func (c *captureSink) Snapshot() []heuristics.Alert {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]heuristics.Alert, len(c.alerts))
	copy(out, c.alerts)
	return out
}

// NewCaptureSink returns a sink suitable for sentry.WithSink that the
// harness can later read from.
func NewCaptureSink() interface {
	Emit([]heuristics.Alert)
	Snapshot() []heuristics.Alert
} {
	return &captureSink{}
}

// Play feeds every event in evs into m, in time order. Caller is
// responsible for constructing m with a sink it can inspect.
func Play(m Manager, evs []*events.Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		return evs[i].Time < evs[j].Time
	})
	for _, e := range evs {
		m.Observe(e)
	}
}

// Score determines whether the alerts attributable to one scenario's
// UID match its expected label.
func Score(s Scenario, uid string, all []heuristics.Alert) Result {
	mine := make([]heuristics.Alert, 0, len(all))
	for _, a := range all {
		if a.UID == uid {
			mine = append(mine, a)
		}
	}
	r := Result{Scenario: s, Alerts: mine}
	if s.Label == LabelBenign {
		r.Detected = len(mine) == 0
		return r
	}
	want := string(s.Label)
	for _, a := range mine {
		if a.Kind == want {
			r.Detected = true
			break
		}
	}
	return r
}

// MakeRNG returns a deterministic RNG so the same seed produces the
// same event stream every run. CI repeatability depends on this.
func MakeRNG(seed int64) *rand.Rand {
	return rand.New(rand.NewSource(seed))
}

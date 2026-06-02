package sim_test

import (
	"sort"
	"strconv"
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/events"
	"backend/sentry/heuristics"
	"backend/sentry/sim"
)

// captureSink records every alert; matches the sentry.AlertSink contract.
type captureSink struct {
	alerts []heuristics.Alert
}

func (c *captureSink) Emit(a []heuristics.Alert) {
	c.alerts = append(c.alerts, a...)
}

func alertKinds(as []heuristics.Alert) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.Kind
	}
	return out
}

func runScenario(t *testing.T, s sim.Scenario, seed int64) sim.Result {
	t.Helper()
	rng := sim.MakeRNG(seed)
	sink := &captureSink{}
	m := sentry.NewManager(sentry.WithSink(sink))

	uid := "S" + strconv.FormatInt(seed, 10)
	nick := s.NickPrefix + strconv.FormatInt(seed, 10)
	startAt := time.Unix(1_700_000_000, 0)

	evs := s.Generate(uid, nick, startAt, rng)
	sim.Play(m, evs)
	return sim.Score(s, uid, sink.alerts)
}

// TestAllScenariosDetected runs each canonical scenario and asserts
// the L1 layer either fires the expected label or stays silent for
// LabelBenign. Failure here means a rule's threshold drifted out of
// alignment with its scenario.
func TestAllScenariosDetected(t *testing.T) {
	for _, s := range sim.AllScenarios {
		s := s
		t.Run(s.Name, func(t *testing.T) {
			r := runScenario(t, s, 1)
			if !r.Detected {
				t.Fatalf("%s: expected label %q to fire; got alerts=%v",
					s.Name, s.Label, alertKinds(r.Alerts))
			}
		})
	}
}

// TestBenignDoesNotFireUnderJitter: re-run the benign scenario with
// several seeds. Flakiness here means the L1 thresholds are too tight
// for varied-but-normal users.
func TestBenignDoesNotFireUnderJitter(t *testing.T) {
	for seed := int64(1); seed <= 10; seed++ {
		r := runScenario(t, sim.BenignChat, seed)
		if len(r.Alerts) != 0 {
			t.Fatalf("seed=%d: benign user fired alerts: %v", seed, alertKinds(r.Alerts))
		}
	}
}

// TestMultiUserMix plays attackers interleaved with benign users
// through one Manager. UID-keyed scoring must isolate findings so the
// benign user picks up nothing while attackers each get their label.
func TestMultiUserMix(t *testing.T) {
	sink := &captureSink{}
	m := sentry.NewManager(sentry.WithSink(sink))
	startAt := time.Unix(1_700_010_000, 0)

	mix := []sim.Scenario{
		sim.BenignChat,
		sim.FloodSpammer,
		sim.RepeatSpammer,
		sim.LinkDropper,
	}
	type slot struct {
		s   sim.Scenario
		uid string
	}
	slots := make([]slot, len(mix))
	var combined []*events.Event
	for i, s := range mix {
		uid := "MX" + strconv.Itoa(i)
		nick := s.NickPrefix + strconv.Itoa(i)
		slots[i] = slot{s: s, uid: uid}
		rng := sim.MakeRNG(int64(100 + i))
		combined = append(combined, s.Generate(uid, nick, startAt, rng)...)
	}
	sort.SliceStable(combined, func(i, j int) bool {
		return combined[i].Time < combined[j].Time
	})
	for _, e := range combined {
		m.Observe(e)
	}

	for _, sl := range slots {
		r := sim.Score(sl.s, sl.uid, sink.alerts)
		if !r.Detected {
			t.Errorf("%s: not detected under multi-user mix; alerts=%v",
				sl.s.Name, alertKinds(r.Alerts))
		}
	}
}

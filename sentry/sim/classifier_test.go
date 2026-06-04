package sim_test

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/anomaly"
	"backend/sentry/classifier"
	"backend/sentry/sim"
)

// labelStore maps UID -> label for the simulator's training runs.
// Safe for concurrent updates so it can be shared across scenarios.
type labelStore struct {
	mu sync.RWMutex
	m  map[string]float64
}

func newLabelStore() *labelStore { return &labelStore{m: map[string]float64{}} }
func (l *labelStore) Set(uid string, label float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[uid] = label
}
func (l *labelStore) Lookup(uid string) (float64, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	v, ok := l.m[uid]
	return v, ok
}

// TestL3LearnsCanonicalScenarios trains the classifier on every
// canonical scenario (benign labeled 0, attacker labeled 1), then
// runs fresh seeds of each scenario through it -- the classifier
// must produce high probability on the attackers and low on benign.
func TestL3LearnsCanonicalScenarios(t *testing.T) {
	labels := newLabelStore()
	clf := classifier.NewModel()
	clf.SetLearningRate(0.02) // gentle; bigger L2 effective regulariser

	sink := &captureSink{}
	const threshold = 0.85
	m := sentry.NewManager(
		sentry.WithSink(sink),
		sentry.WithClassifier(clf, threshold),
		sentry.WithClassifierLabeler(labels.Lookup),
	)

	startAt := time.Unix(1_700_040_000, 0)

	// Multiple passes over the scenarios to give SGD enough updates
	// to converge. Each pass uses different seeds so we're not
	// training on the same byte-for-byte event stream.
	//
	// Class balance matters: attacker scenarios produce many more
	// feature-bearing events than benign (flood = 80 msgs, benign =
	// 8), so naively training one of each per pass yields a ~15:1
	// gradient imbalance that pushes the bias toward "always
	// malicious". We compensate by running multiple benign instances
	// per pass (each with a fresh seed) so the gradient counts are
	// roughly even.
	const benignPerPass = 40
	for pass := 1; pass <= 60; pass++ {
		// Benign block: rotate through ALL benign scenarios in the
		// canonical set so the classifier sees every benign shape.
		benignScens := []sim.Scenario{sim.BenignChat, sim.MarkovBenign}
		for _, s := range sim.AllScenarios {
			if s.Label == sim.LabelBenign && s.Name != sim.BenignChat.Name {
				benignScens = append(benignScens, s)
			}
		}
		for b := 0; b < benignPerPass; b++ {
			seed := int64(pass*1000 + b)
			rng := sim.MakeRNG(seed)
			uid := "TRN-B-" + strconv.Itoa(pass) + "-" + strconv.Itoa(b)
			scen := benignScens[b%len(benignScens)]
			nick := scen.NickPrefix + "TRN" + strconv.Itoa(int(seed))
			labels.Set(uid, 0)
			sim.Play(m, scen.Generate(uid, nick, startAt, rng))
		}
		// Attacker block: each non-benign scenario once.
		for scenIdx, s := range sim.AllScenarios {
			if s.Label == sim.LabelBenign {
				continue
			}
			seed := int64(pass*100 + scenIdx)
			rng := sim.MakeRNG(seed)
			uid := "TRN-A-" + strconv.Itoa(pass) + "-" + strconv.Itoa(scenIdx)
			nick := s.NickPrefix + "TRN" + strconv.Itoa(int(seed))
			labels.Set(uid, 1)
			sim.Play(m, s.Generate(uid, nick, startAt, rng))
		}
	}

	// Evaluation: held-out seeds. Disable training labels for these
	// users so SGD doesn't update on the test set.
	type result struct {
		scenario string
		label    float64
		maxP     float64 // peak score the classifier ever produced
	}
	evalResults := make([]result, 0, len(sim.AllScenarios))
	for scenIdx, s := range sim.AllScenarios {
		uid := "EVAL-" + strconv.Itoa(scenIdx)
		nick := s.NickPrefix + "EVAL" + strconv.Itoa(scenIdx)
		rng := sim.MakeRNG(int64(9999 + scenIdx))
		evs := s.Generate(uid, nick, startAt.Add(2*time.Hour), rng)
		// Don't set any label for EVAL UIDs -- classifierLabeler
		// returns (0, false), no SGD update happens.
		sink.alerts = nil
		sim.Play(m, evs)

		var maxP float64
		for _, a := range sink.alerts {
			if a.UID == uid && a.Kind == "ml" {
				if a.Confidence > maxP {
					maxP = a.Confidence
				}
			}
		}
		label := 1.0
		if s.Label == sim.LabelBenign {
			label = 0
		}
		evalResults = append(evalResults, result{
			scenario: s.Name, label: label, maxP: maxP,
		})
	}

	// Assertions: at the chosen threshold (0.7), all attacker
	// scenarios should have produced at least one ml alert; the
	// benign scenario should not have.
	for _, r := range evalResults {
		t.Logf("scenario=%s label=%v maxP=%.3f", r.scenario, r.label, r.maxP)
	}
	for _, r := range evalResults {
		switch {
		case r.label == 1 && r.maxP < threshold:
			t.Errorf("attacker %s not classified: maxP=%.3f", r.scenario, r.maxP)
		case r.label == 0 && r.maxP >= threshold:
			t.Errorf("benign %s false-positive: maxP=%.3f", r.scenario, r.maxP)
		}
	}
}

// TestL3PersistAndRestore: after training, snapshot + reload must
// yield identical predictions on a fixed input vector.
func TestL3PersistAndRestore(t *testing.T) {
	clf := classifier.NewModel()
	clf.SetLearningRate(0.1)
	for i := 0; i < 200; i++ {
		label := 0.0
		base := 1.0
		if i%2 == 0 {
			label = 1.0
			base = 30.0
		}
		fv := classifier.FeatureMap{
			anomaly.FeatMsgRate: base,
		}
		clf.Train(fv, label)
	}
	probe := classifier.FeatureMap{anomaly.FeatMsgRate: 25.0}
	before := clf.Score(probe)

	snap := clf.Snapshot()
	other := classifier.NewModel()
	other.LoadSnapshot(snap)
	after := other.Score(probe)

	if before != after {
		t.Fatalf("score diverged after reload: before=%v after=%v", before, after)
	}
}

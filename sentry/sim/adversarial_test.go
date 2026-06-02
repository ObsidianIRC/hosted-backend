package sim_test

import (
	"strconv"
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/anomaly"
	"backend/sentry/classifier"
	"backend/sentry/sim"
)

// TestAdversarialHeldOut trains on AllScenarios but evaluates against
// scenarios in AdversarialScenarios that were NEVER in training. The
// classifier should still produce a high probability on these
// because they're built from the same feature primitives the
// canonical attacks use.
//
// This is the strongest test of generalisation: the model should not
// just memorise scenario shapes but learn the underlying patterns of
// abuse.
func TestAdversarialHeldOut(t *testing.T) {
	labels := newLabelStore()
	am := anomaly.NewModel()
	am.MinSamples = 30
	clf := classifier.NewModel()
	clf.SetLearningRate(0.02)

	m := sentry.NewManager(
		sentry.WithAnomalyModel(am),
		sentry.WithClassifier(clf, 0.85),
		sentry.WithClassifierLabeler(labels.Lookup),
	)

	startAt := time.Unix(1_700_500_000, 0)
	benignScens := []sim.Scenario{sim.BenignChat, sim.MarkovBenign}
	for _, s := range sim.AllScenarios {
		if s.Label == sim.LabelBenign && s.Name != sim.BenignChat.Name {
			benignScens = append(benignScens, s)
		}
	}
	for pass := 1; pass <= 60; pass++ {
		for b := 0; b < 40; b++ {
			seed := int64(pass*1000 + b)
			uid := "TRN-B-" + strconv.Itoa(pass) + "-" + strconv.Itoa(b)
			labels.Set(uid, 0)
			scen := benignScens[b%len(benignScens)]
			sim.Play(m, scen.Generate(uid, "x", startAt, sim.MakeRNG(seed)))
		}
		for scenIdx, s := range sim.AllScenarios {
			if s.Label == sim.LabelBenign {
				continue
			}
			seed := int64(pass*100 + scenIdx)
			uid := "TRN-A-" + strconv.Itoa(pass) + "-" + strconv.Itoa(scenIdx)
			labels.Set(uid, 1)
			sim.Play(m, s.Generate(uid, "a", startAt, sim.MakeRNG(seed)))
		}
	}

	// Now eval on adversarial scenarios -- these UIDs have no labels
	// so the classifier won't train on them.
	type result struct {
		name string
		maxP float64
	}
	var results []result
	for idx, s := range sim.AdversarialScenarios {
		sink := &captureSink{}
		_ = sink
		// Need a fresh manager so prior eval doesn't leak alerts.
		// Actually we just want classifier scores -- use a different
		// uid each time so it's distinct in the manager.
		uid := "ADV-" + strconv.Itoa(idx)
		// Drive events through the same manager (already trained);
		// L3 will score, no label = no training.
		evs := s.Generate(uid, "evader", startAt.Add(2*time.Hour+time.Duration(idx)*time.Hour), sim.MakeRNG(int64(33333+idx)))
		sim.Play(m, evs)
		// Compute the final score using the explainability path so
		// we can report a real number even when no ml alert fires.
		rep := m.Explain(uid)
		results = append(results, result{name: s.Name, maxP: rep.MaliceProb})
	}

	for _, r := range results {
		t.Logf("held-out adversary %s: p=%.3f", r.name, r.maxP)
	}
	for _, r := range results {
		if r.maxP < 0.5 {
			t.Errorf("model failed to flag held-out adversary %s: p=%.3f", r.name, r.maxP)
		}
	}
}

package sim_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/anomaly"
	"backend/sentry/classifier"
	"backend/sentry/explain"
	"backend/sentry/sim"
)

func TestExplainProducesReasoning(t *testing.T) {
	labels := newLabelStore()
	am := anomaly.NewModel()
	am.MinSamples = 30
	clf := classifier.NewModel()
	clf.SetLearningRate(0.1)

	m := sentry.NewManager(
		sentry.WithAnomalyModel(am),
		sentry.WithClassifier(clf, 0.7),
		sentry.WithClassifierLabeler(labels.Lookup),
	)
	startAt := time.Unix(1_700_100_000, 0)
	for pass := 1; pass <= 6; pass++ {
		for b := 0; b < 18; b++ {
			seed := int64(pass*1000 + b)
			uid := "B-" + strconv.Itoa(pass) + "-" + strconv.Itoa(b)
			labels.Set(uid, 0)
			sim.Play(m, sim.BenignChat.Generate(uid, "x", startAt, sim.MakeRNG(seed)))
		}
		for scenIdx, s := range sim.AllScenarios {
			if s.Label == sim.LabelBenign {
				continue
			}
			seed := int64(pass*100 + scenIdx)
			uid := "A-" + strconv.Itoa(pass) + "-" + strconv.Itoa(scenIdx)
			labels.Set(uid, 1)
			sim.Play(m, s.Generate(uid, "a", startAt, sim.MakeRNG(seed)))
		}
	}

	uid := "EVALEXPL"
	sim.Play(m, sim.FloodSpammer.Generate(uid, "spammer", startAt.Add(time.Hour), sim.MakeRNG(11)))

	rep := m.Explain(uid)
	if rep.Nick == "" {
		t.Fatalf("explain returned empty report (unknown UID?)")
	}
	if rep.MaliceProb < 0.7 {
		t.Errorf("expected high malice prob on attacker, got %.3f", rep.MaliceProb)
	}
	if len(rep.Top) == 0 {
		t.Fatalf("expected at least one feature contribution")
	}
	formatted := strings.ToLower(explain.Format(rep, 5))
	if !strings.Contains(formatted, "spammer") {
		t.Errorf("formatted report missing nick: %q", formatted)
	}
	if !strings.Contains(formatted, "top features") {
		t.Errorf("formatted report missing top features section: %q", formatted)
	}
}

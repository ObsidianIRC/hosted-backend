package sim_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/anomaly"
	"backend/sentry/heuristics"
	"backend/sentry/sim"
)

// TestL2DetectsFloodAfterBenignTraining: pre-train an anomaly model
// on 40 benign users so the MsgRate baseline is well-warmed, then run
// a flood-spammer through the same Manager and assert an L2 alert
// (anomaly:msg_rate_per_min) fires alongside the L1 "flood" label.
func TestL2DetectsFloodAfterBenignTraining(t *testing.T) {
	model := anomaly.NewModel()
	model.MinSamples = 30
	model.ZThreshold = 3.0

	// Pre-train on benign-only traffic.
	sink := &captureSink{}
	m := sentry.NewManager(
		sentry.WithSink(sink),
		sentry.WithAnomalyModel(model),
		sentry.WithAnomalyTrainOnly(true),
	)
	startAt := time.Unix(1_700_020_000, 0)
	for seed := 1; seed <= 40; seed++ {
		rng := sim.MakeRNG(int64(seed))
		uid := "B" + strconv.Itoa(seed)
		nick := sim.BenignChat.NickPrefix + strconv.Itoa(seed)
		evs := sim.BenignChat.Generate(uid, nick, startAt, rng)
		sim.Play(m, evs)
	}

	// Confirm the L1 layer was silent on all benign training data --
	// if it wasn't, the baseline includes attacker patterns and our
	// L2 test is meaningless.
	for _, a := range sink.alerts {
		t.Fatalf("L1 fired on benign training data: %+v", a)
	}
	if model.Samples(anomaly.FeatMsgRate) < model.MinSamples {
		t.Fatalf("baseline never warmed: msg_rate samples=%d",
			model.Samples(anomaly.FeatMsgRate))
	}

	// Switch out of training mode and run the attacker.
	m.SetAnomalyTrainOnly(false)
	sink.alerts = nil
	rng := sim.MakeRNG(99)
	attackerUID := "X1"
	attackerNick := sim.FloodSpammer.NickPrefix + "99"
	evs := sim.FloodSpammer.Generate(attackerUID, attackerNick, startAt.Add(time.Hour), rng)
	sim.Play(m, evs)

	var sawL1Flood, sawL2 bool
	for _, a := range sink.alerts {
		if a.UID != attackerUID {
			continue
		}
		switch {
		case a.Kind == "flood":
			sawL1Flood = true
		case strings.HasPrefix(a.Kind, "anomaly:"):
			sawL2 = true
		}
	}
	if !sawL1Flood {
		t.Errorf("expected L1 flood alert, got kinds=%v", alertKinds(sink.alerts))
	}
	if !sawL2 {
		t.Errorf("expected at least one L2 anomaly:* alert on attacker, got kinds=%v",
			alertKinds(sink.alerts))
	}
}

// TestL2DoesNotFireOnBenignAfterTraining: after training, a fresh
// benign user must not produce L2 anomaly alerts.
func TestL2DoesNotFireOnBenignAfterTraining(t *testing.T) {
	model := anomaly.NewModel()
	model.MinSamples = 30
	model.ZThreshold = 3.0

	sink := &captureSink{}
	m := sentry.NewManager(
		sentry.WithSink(sink),
		sentry.WithAnomalyModel(model),
		sentry.WithAnomalyTrainOnly(true),
	)
	startAt := time.Unix(1_700_030_000, 0)
	for seed := 1; seed <= 40; seed++ {
		rng := sim.MakeRNG(int64(seed))
		uid := "B" + strconv.Itoa(seed)
		nick := sim.BenignChat.NickPrefix + strconv.Itoa(seed)
		sim.Play(m, sim.BenignChat.Generate(uid, nick, startAt, rng))
	}

	m.SetAnomalyTrainOnly(false)
	sink.alerts = nil
	rng := sim.MakeRNG(500)
	uid := "Bfresh"
	nick := sim.BenignChat.NickPrefix + "fresh"
	sim.Play(m, sim.BenignChat.Generate(uid, nick, startAt.Add(2*time.Hour), rng))

	for _, a := range sink.alerts {
		if a.UID == uid {
			t.Errorf("L2 false-positive on benign user: %v", alertKinds([]heuristics.Alert{a}))
		}
	}
}

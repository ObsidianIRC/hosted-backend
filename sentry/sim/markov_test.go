package sim_test

import (
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/sim"
)

// TestMarkovBenignDoesNotAlertAnyRule: across many seeds, the
// Markov-driven benign chatter must NOT trip any L1 rule. If this
// fails the corpus has accidentally drifted into a pattern (e.g.
// always-uppercase phrases) that crosses a heuristic threshold.
func TestMarkovBenignDoesNotAlertAnyRule(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		sink := &captureSink{}
		m := sentry.NewManager(sentry.WithSink(sink))
		rng := sim.MakeRNG(seed)
		uid := "M" + intToStrSeed(seed)
		nick := "irc" + intToStrSeed(seed)
		sim.Play(m, sim.MarkovBenign.Generate(uid, nick, time.Unix(1_700_200_000, 0), rng))
		if len(sink.alerts) != 0 {
			t.Errorf("seed=%d: markov benign fired alerts: %v", seed, alertKinds(sink.alerts))
		}
	}
}

func intToStrSeed(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

package anomaly

import (
	"math"
	"math/rand"
	"testing"
)

// Tolerance for floating-point comparisons in stat tests.
const eps = 1e-9

// TestWelfordMatchesBatch: Welford's online mean/variance must agree
// with the textbook two-pass formulas on a fixed sample set.
func TestWelfordMatchesBatch(t *testing.T) {
	samples := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	var w Welford
	for _, x := range samples {
		w.Observe(x)
	}
	// Batch mean.
	sum := 0.0
	for _, x := range samples {
		sum += x
	}
	mean := sum / float64(len(samples))
	if math.Abs(w.Mean-mean) > eps {
		t.Fatalf("mean: got %v want %v", w.Mean, mean)
	}
	// Batch variance (unbiased).
	sq := 0.0
	for _, x := range samples {
		d := x - mean
		sq += d * d
	}
	wantVar := sq / float64(len(samples)-1)
	if math.Abs(w.Variance()-wantVar) > 1e-6 {
		t.Fatalf("variance: got %v want %v", w.Variance(), wantVar)
	}
}

// TestWelfordMergeMatchesSequential: parallel merge of two halves
// must agree with the sequential single-stream result.
func TestWelfordMergeMatchesSequential(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	var seq, a, b Welford
	for i := 0; i < 200; i++ {
		x := rng.NormFloat64()
		seq.Observe(x)
		if i < 100 {
			a.Observe(x)
		} else {
			b.Observe(x)
		}
	}
	merged := a
	merged.Merge(b)
	if merged.N != seq.N {
		t.Fatalf("N: merged=%d seq=%d", merged.N, seq.N)
	}
	if math.Abs(merged.Mean-seq.Mean) > 1e-9 {
		t.Fatalf("mean: merged=%v seq=%v", merged.Mean, seq.Mean)
	}
	if math.Abs(merged.Variance()-seq.Variance()) > 1e-6 {
		t.Fatalf("var: merged=%v seq=%v", merged.Variance(), seq.Variance())
	}
}

// TestModelDetectsOutlier: train on a benign distribution, run an
// extreme sample, expect Anomalous() to flag the right feature.
func TestModelDetectsOutlier(t *testing.T) {
	m := NewModel()
	m.MinSamples = 30
	rng := rand.New(rand.NewSource(1))

	// Train baseline: msg_rate ~ N(2, 0.5), upper_ratio ~ N(0.1, 0.05).
	for i := 0; i < 200; i++ {
		m.Observe(FeatureMap{
			FeatMsgRate:    2 + rng.NormFloat64()*0.5,
			FeatUpperRatio: 0.1 + rng.NormFloat64()*0.05,
		})
	}

	// A flood-style sample: msg_rate=40 (way above baseline), normal
	// upper_ratio. Must flag FeatMsgRate but NOT FeatUpperRatio.
	hits := m.Anomalous(FeatureMap{
		FeatMsgRate:    40,
		FeatUpperRatio: 0.1,
	})
	var sawMsgRate, sawUpper bool
	for _, f := range hits {
		if f.Feature == FeatMsgRate {
			sawMsgRate = true
		}
		if f.Feature == FeatUpperRatio {
			sawUpper = true
		}
	}
	if !sawMsgRate {
		t.Fatalf("flood sample failed to trip FeatMsgRate; hits=%v", hits)
	}
	if sawUpper {
		t.Fatalf("normal upper_ratio falsely flagged; hits=%v", hits)
	}
}

// TestModelHonorsMinSamples: while the model is warm-up, no feature
// should produce a score even if values are extreme.
func TestModelHonorsMinSamples(t *testing.T) {
	m := NewModel()
	m.MinSamples = 100
	m.Observe(FeatureMap{FeatMsgRate: 1})
	m.Observe(FeatureMap{FeatMsgRate: 2})
	hits := m.Anomalous(FeatureMap{FeatMsgRate: 9999})
	if len(hits) != 0 {
		t.Fatalf("under MinSamples, expected no hits, got %v", hits)
	}
}

// TestSnapshotRoundTrip: persisting and reloading must yield bit-
// identical scoring behavior.
func TestSnapshotRoundTrip(t *testing.T) {
	m := NewModel()
	m.MinSamples = 5
	for i := 0; i < 50; i++ {
		m.Observe(FeatureMap{FeatMsgRate: float64(i)})
	}
	before := m.Score(FeatureMap{FeatMsgRate: 100})

	snap := m.Snapshot()
	m2 := NewModel()
	m2.MinSamples = 5
	m2.LoadSnapshot(snap)
	after := m2.Score(FeatureMap{FeatMsgRate: 100})

	if math.Abs(before[FeatMsgRate]-after[FeatMsgRate]) > 1e-9 {
		t.Fatalf("score after reload diverged: before=%v after=%v",
			before[FeatMsgRate], after[FeatMsgRate])
	}
}

package classifier

import (
	"math/rand"
	"testing"
)

// TestLearnsLinearlySeparable: a synthetic 2-feature dataset that's
// linearly separable should reach >95% accuracy after a few hundred
// SGD passes.
func TestLearnsLinearlySeparable(t *testing.T) {
	m := NewModel()
	rng := rand.New(rand.NewSource(7))

	// Class 0 (benign): feat_a low, feat_b low.
	// Class 1 (malicious): feat_a high, feat_b high.
	gen := func(label float64) FeatureMap {
		base := 0.0
		if label > 0.5 {
			base = 5.0
		}
		return FeatureMap{
			"feat_a": base + rng.NormFloat64()*0.5,
			"feat_b": base + rng.NormFloat64()*0.5,
		}
	}

	// Train: 800 samples balanced.
	for i := 0; i < 800; i++ {
		label := float64(i % 2)
		m.Train(gen(label), label)
	}

	// Evaluate accuracy on a fresh 200-sample test set.
	correct := 0
	for i := 0; i < 200; i++ {
		label := float64(i % 2)
		p := m.Score(gen(label))
		pred := 0.0
		if p > 0.5 {
			pred = 1.0
		}
		if pred == label {
			correct++
		}
	}
	if correct < 190 {
		t.Fatalf("classifier failed to converge: %d/200 correct", correct)
	}
}

// TestSnapshotRoundTrip: persisted+reloaded model must score
// identically to the original.
func TestSnapshotRoundTrip(t *testing.T) {
	m := NewModel()
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 100; i++ {
		label := float64(i % 2)
		fv := FeatureMap{
			"x": float64(label*4) + rng.NormFloat64(),
			"y": rng.NormFloat64(),
		}
		m.Train(fv, label)
	}
	test := FeatureMap{"x": 3.5, "y": 0.1}
	before := m.Score(test)

	snap := m.Snapshot()
	m2 := NewModel()
	m2.LoadSnapshot(snap)
	after := m2.Score(test)

	if before != after {
		t.Fatalf("score after reload diverged: before=%v after=%v", before, after)
	}
	if m2.Steps() != m.Steps() {
		t.Fatalf("steps after reload diverged: before=%d after=%d", m.Steps(), m2.Steps())
	}
}

// TestSigmoidClamp: extreme logits must not produce NaN.
func TestSigmoidClamp(t *testing.T) {
	cases := []struct {
		z    float64
		want float64
	}{
		{1000, 1},
		{-1000, 0},
		{0, 0.5},
	}
	for _, c := range cases {
		got := sigmoid(c.z)
		if got != c.want {
			t.Errorf("sigmoid(%v) = %v, want %v", c.z, got, c.want)
		}
	}
}

// TestSoftLabels: feeding intermediate labels (e.g. 0.7 for
// "L1 fired with confidence 0.7") must shift the prediction toward
// that label without saturating.
func TestSoftLabels(t *testing.T) {
	m := NewModel()
	m.SetLearningRate(0.2)
	for i := 0; i < 200; i++ {
		m.Train(FeatureMap{"x": 1.0}, 0.7)
	}
	p := m.Score(FeatureMap{"x": 1.0})
	if p < 0.55 || p > 0.85 {
		t.Errorf("soft-label score = %v, want ~0.7", p)
	}
}

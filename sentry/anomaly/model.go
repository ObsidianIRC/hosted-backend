package anomaly

import (
	"sync"
)

// FeatureName is the canonical key for a single feature dimension.
// The string MUST stay stable across versions because trained models
// are persisted by key; renaming a feature breaks loaded baselines.
type FeatureName string

const (
	FeatMsgRate        FeatureName = "msg_rate_per_min"
	FeatJoinRate       FeatureName = "join_rate_per_min"
	FeatMsgLenMean     FeatureName = "msg_len_mean"
	FeatMsgLenVar      FeatureName = "msg_len_var"
	FeatDistinctHashes FeatureName = "distinct_hashes_ratio"
	FeatUniqueChannels FeatureName = "unique_channels"
	FeatUpperRatio     FeatureName = "upper_ratio_mean"
	FeatURLCount       FeatureName = "url_count"
	FeatCTCPCount      FeatureName = "ctcp_count"
	FeatIdleBurst      FeatureName = "idle_burst_score"
	FeatNickFlipRate   FeatureName = "nick_flip_rate"
	FeatHopRate        FeatureName = "hop_rate"
)

// AllFeatures enumerates every dimension the model tracks. Iteration
// order is fixed for reproducible model dumps.
var AllFeatures = []FeatureName{
	FeatMsgRate,
	FeatJoinRate,
	FeatMsgLenMean,
	FeatMsgLenVar,
	FeatDistinctHashes,
	FeatUniqueChannels,
	FeatUpperRatio,
	FeatURLCount,
	FeatCTCPCount,
	FeatIdleBurst,
	FeatNickFlipRate,
	FeatHopRate,
}

// Model is an L2 anomaly detector: one Welford accumulator per
// feature, plus configuration controlling when a z-score is "anomalous
// enough" to fire.
//
// Safe for concurrent Observe/Score from multiple goroutines via a
// single sync.RWMutex; the per-feature Welford updates happen under
// the write lock during Observe.
type Model struct {
	mu sync.RWMutex
	// accumulators[f] is the running stats for feature f. Modeled as
	// a map (not array) so a feature can be added later without
	// invalidating persisted models.
	accumulators map[FeatureName]*Welford

	// ZThreshold is the per-feature z-score above which we consider a
	// dimension "anomalous". Defaults to 3.0 in NewModel.
	ZThreshold float64

	// MinSamples is the minimum N before any feature contributes a
	// score. Prevents wild z-scores while the baseline is still warm.
	MinSamples uint64
}

// NewModel returns a model with empty accumulators and sane defaults.
func NewModel() *Model {
	m := &Model{
		accumulators: make(map[FeatureName]*Welford, len(AllFeatures)),
		ZThreshold:   3.0,
		MinSamples:   30,
	}
	for _, f := range AllFeatures {
		m.accumulators[f] = &Welford{}
	}
	return m
}

// FeatureMap is the input form for both training and scoring: a flat
// {feature -> value} mapping. Callers translate their own struct
// (e.g. sentry.FeatureVector) into this before handing it over.
type FeatureMap map[FeatureName]float64

// Observe folds one benign-labeled sample into the baseline. Callers
// MUST be sure this user is benign -- attacker samples poison the
// distribution and degrade detection.
func (m *Model) Observe(fv FeatureMap) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for f, v := range fv {
		acc, ok := m.accumulators[f]
		if !ok {
			acc = &Welford{}
			m.accumulators[f] = acc
		}
		acc.Observe(v)
	}
}

// Score returns the per-feature z-scores of fv against the baseline.
// Features not in the baseline yield 0. Use Anomalous() for a
// threshold decision.
func (m *Model) Score(fv FeatureMap) map[FeatureName]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[FeatureName]float64, len(fv))
	for f, v := range fv {
		acc, ok := m.accumulators[f]
		if !ok || acc.N < m.MinSamples {
			out[f] = 0
			continue
		}
		out[f] = acc.Z(v)
	}
	return out
}

// Anomalous returns the set of features whose |z-score| exceeds
// ZThreshold. Empty slice if nothing is anomalous (or if the model
// is still warming up).
func (m *Model) Anomalous(fv FeatureMap) []Finding {
	zs := m.Score(fv)
	var out []Finding
	for f, z := range zs {
		if z > m.ZThreshold || z < -m.ZThreshold {
			out = append(out, Finding{Feature: f, Z: z})
		}
	}
	return out
}

// Finding pairs a feature key with its measured deviation. Returned
// by Anomalous; consumed by the sentry pipeline to build Alerts.
type Finding struct {
	Feature FeatureName
	Z       float64 // signed deviation in standard deviations
}

// Samples returns how many observations have been folded into the
// given feature. Useful for warm-up checks and observability.
func (m *Model) Samples(f FeatureName) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if acc, ok := m.accumulators[f]; ok {
		return acc.N
	}
	return 0
}

// Snapshot returns a deep copy of the per-feature accumulators. Used
// for persistence -- the caller can json-encode the map and write it
// to disk; loading is just the reverse via LoadSnapshot.
func (m *Model) Snapshot() map[FeatureName]Welford {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[FeatureName]Welford, len(m.accumulators))
	for f, acc := range m.accumulators {
		out[f] = *acc
	}
	return out
}

// LoadSnapshot replaces the model's accumulators with those in s.
func (m *Model) LoadSnapshot(s map[FeatureName]Welford) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accumulators = make(map[FeatureName]*Welford, len(s))
	for f, w := range s {
		w := w
		m.accumulators[f] = &w
	}
}

// Package anomaly is the L2 detection layer: an online,
// distribution-free anomaly model that scores a user's feature
// vector against a learned baseline of "normal".
//
// The baseline is built from feature vectors of users that the L1
// rules did NOT flag (or that an oper explicitly marked benign).
// During training we feed those vectors in via Update; during scoring
// we ask the model for per-feature z-scores, which the sentry
// pipeline turns into alert signals.
//
// We use Welford's algorithm so the update is O(features), numerically
// stable for very long streams, and never needs to retain raw samples.
package anomaly

import "math"

// Welford holds the running statistics needed to compute mean and
// variance over an unbounded stream of samples. The classic recurrence:
//
//	count += 1
//	delta = x - mean
//	mean  += delta / count
//	delta2 = x - mean
//	M2    += delta * delta2
//
// After N observations: mean is the sample mean, M2/(N-1) is the
// (unbiased) sample variance.
type Welford struct {
	N    uint64
	Mean float64
	M2   float64
}

// Observe folds one sample into the running statistics.
func (w *Welford) Observe(x float64) {
	w.N++
	delta := x - w.Mean
	w.Mean += delta / float64(w.N)
	delta2 := x - w.Mean
	w.M2 += delta * delta2
}

// Variance returns the unbiased sample variance, or 0 when fewer than
// two samples have been seen.
func (w *Welford) Variance() float64 {
	if w.N < 2 {
		return 0
	}
	return w.M2 / float64(w.N-1)
}

// StdDev returns the unbiased sample standard deviation, or 0 when
// fewer than two samples are present.
func (w *Welford) StdDev() float64 {
	return math.Sqrt(w.Variance())
}

// Z returns the z-score of x against the running mean and stddev. If
// the population stddev is effectively zero or N<2, returns 0 (no
// signal -- avoids dividing by a meaningless denominator).
func (w *Welford) Z(x float64) float64 {
	sd := w.StdDev()
	if sd < 1e-9 || w.N < 2 {
		return 0
	}
	return (x - w.Mean) / sd
}

// Merge folds the statistics of other into w using Chan et al.'s
// parallel algorithm. Useful when training in shards (e.g. one
// goroutine per scenario) and combining at the end.
func (w *Welford) Merge(other Welford) {
	if other.N == 0 {
		return
	}
	if w.N == 0 {
		*w = other
		return
	}
	delta := other.Mean - w.Mean
	n := float64(w.N + other.N)
	w.Mean = (w.Mean*float64(w.N) + other.Mean*float64(other.N)) / n
	w.M2 = w.M2 + other.M2 + delta*delta*float64(w.N)*float64(other.N)/n
	w.N += other.N
}

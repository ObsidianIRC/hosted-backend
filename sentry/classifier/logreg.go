// Package classifier is the L3 detection layer: an online logistic
// regression model trained via stochastic gradient descent. It eats
// (FeatureMap, label) pairs and outputs a calibrated probability of
// malice for any future feature vector.
//
// The "online" bit matters: training uses one labeled sample at a
// time and never retains raw samples, which is what lets us:
//
//   1. train continuously from simulator-labeled scenarios,
//   2. learn from operator feedback (Ban/Kick/Ignore buttons) as it
//      arrives, without rebuilding the model from scratch, and
//   3. keep memory bounded (just the weight vector + bias).
//
// The model uses standard logistic regression:
//
//   p = sigmoid(w . x + b)
//   loss = -[y log p + (1-y) log(1-p)]            // binary cross-entropy
//   gradient_w = (p - y) * x                       // per-feature SGD update
//   gradient_b = (p - y)
//
// A small L2 regularizer (weight decay) keeps weights from growing
// unboundedly as the model trains on more data.
package classifier

import (
	"math"
	"sync"

	"backend/sentry/anomaly"
)

// FeatureName re-exports anomaly.FeatureName so callers don't have to
// reach into the anomaly package just to construct a sample.
type FeatureName = anomaly.FeatureName

// FeatureMap re-exports anomaly.FeatureMap for the same reason.
type FeatureMap = anomaly.FeatureMap

// Stacked L1 features: L3 also accepts one binary feature per L1 rule
// name, prefixed "l1:". Lets the classifier learn that an L1 hit
// reinforces other suspicious signals.
const L1FeaturePrefix = "l1:"

// Model is an L3 binary classifier. Safe for concurrent Train / Score
// via an RWMutex; Train takes the write lock per sample, Score takes
// the read lock.
type Model struct {
	mu       sync.RWMutex
	weights  map[FeatureName]float64
	bias     float64
	lr       float64 // learning rate
	l2       float64 // L2 regularizer coefficient (weight decay)
	steps    uint64  // total SGD updates performed (for observability)
}

// NewModel returns a fresh model with zero weights and sane SGD
// defaults: lr=0.05 (aggressive enough to learn from O(100s) samples),
// L2 coefficient 1e-4 (light decay).
func NewModel() *Model {
	return &Model{
		weights: make(map[FeatureName]float64, 16),
		lr:      0.05,
		l2:      1e-4,
	}
}

// SetLearningRate adjusts the per-step learning rate. Lower it as the
// model matures to fine-tune; raise it after a flood of new
// operator-confirmed labels to learn the new pattern faster.
func (m *Model) SetLearningRate(lr float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lr = lr
}

// SetRegularizer adjusts the L2 weight-decay coefficient.
func (m *Model) SetRegularizer(l2 float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.l2 = l2
}

// Steps returns how many SGD updates have been performed.
func (m *Model) Steps() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.steps
}

// Score returns the model's predicted probability of malice for fv
// in [0, 1]. A fresh model with no training returns 0.5.
func (m *Model) Score(fv FeatureMap) float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	z := m.bias
	for f, v := range fv {
		if w, ok := m.weights[f]; ok {
			z += w * v
		}
	}
	return sigmoid(z)
}

// Train folds one labeled sample into the model via one SGD step.
// label MUST be 0 (benign) or 1 (malicious); intermediate values are
// allowed and treated as soft labels (useful when an L1 alert with
// confidence c is fed in as label=c).
func (m *Model) Train(fv FeatureMap, label float64) {
	if label < 0 {
		label = 0
	} else if label > 1 {
		label = 1
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Forward pass.
	z := m.bias
	for f, v := range fv {
		z += m.weights[f] * v
	}
	p := sigmoid(z)

	// Gradient of binary cross-entropy w.r.t. logits is (p - y).
	dz := p - label

	// Update per-feature weights and ensure the key is registered.
	for f, v := range fv {
		w := m.weights[f]
		// SGD with L2 decay.
		w -= m.lr * (dz*v + m.l2*w)
		m.weights[f] = w
	}
	// Apply a (weaker) decay to bias so a wildly class-imbalanced
	// training stream can't saturate the intercept and make the
	// model regress to the majority class.
	m.bias -= m.lr * (dz + m.l2*0.1*m.bias)
	m.steps++
}

// TrainBatch is a convenience for warming up the model on synthetic
// scenarios: it just calls Train once per sample. Caller decides the
// presentation order (shuffle for SGD, otherwise pass-through).
func (m *Model) TrainBatch(samples []Sample) {
	for _, s := range samples {
		m.Train(s.Features, s.Label)
	}
}

// Sample is a single labeled training example.
type Sample struct {
	Features FeatureMap
	Label    float64 // 0 = benign, 1 = malicious; soft labels OK
}

// Weights returns a copy of the current weight vector. Useful for
// explainability ("which feature drove this decision?") and for
// persistence.
func (m *Model) Weights() map[FeatureName]float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[FeatureName]float64, len(m.weights))
	for f, w := range m.weights {
		out[f] = w
	}
	return out
}

// Bias returns the model's intercept term.
func (m *Model) Bias() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.bias
}

// Snapshot captures all trainable parameters so the model can be
// persisted and later restored verbatim via LoadSnapshot.
type Snapshot struct {
	Weights map[FeatureName]float64
	Bias    float64
	LR      float64
	L2      float64
	Steps   uint64
}

// Snapshot returns the current state of the model.
func (m *Model) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := Snapshot{
		Weights: make(map[FeatureName]float64, len(m.weights)),
		Bias:    m.bias,
		LR:      m.lr,
		L2:      m.l2,
		Steps:   m.steps,
	}
	for f, w := range m.weights {
		s.Weights[f] = w
	}
	return s
}

// LoadSnapshot restores parameters captured by Snapshot.
func (m *Model) LoadSnapshot(s Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.weights = make(map[FeatureName]float64, len(s.Weights))
	for f, w := range s.Weights {
		m.weights[f] = w
	}
	m.bias = s.Bias
	if s.LR > 0 {
		m.lr = s.LR
	}
	m.l2 = s.L2
	m.steps = s.Steps
}

// sigmoid is the standard logistic squash. We clamp the input to
// [-30, 30] to avoid numerically-zero exp(-x) producing NaN gradients
// when SGD overshoots wildly.
func sigmoid(z float64) float64 {
	if z > 30 {
		return 1
	}
	if z < -30 {
		return 0
	}
	return 1.0 / (1.0 + math.Exp(-z))
}

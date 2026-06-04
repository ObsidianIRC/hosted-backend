// Package explain produces human-readable reasoning for sentry
// decisions. Three audiences:
//
//   - Opers asking "why did sentry kill ($nick)?" -- they get a
//     compact rundown of which layers fired and which features drove
//     the L3 score.
//   - Engineers tuning thresholds -- they get the raw model state.
//   - Auditors checking the decision trail -- they get a stable
//     JSON-able structure.
package explain

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"backend/sentry/anomaly"
	"backend/sentry/classifier"
)

// FeatureContribution is one weight*value term inside the logistic
// regression sum, plus the feature key. The sign tells you which
// direction it pushed the score.
type FeatureContribution struct {
	Feature    classifier.FeatureName
	Value      float64 // raw feature value (post log-scale)
	Weight     float64 // L3 weight
	Contrib    float64 // value * weight (the term in w·x)
	ZScore     float64 // L2 z-score for this feature, 0 if N/A
}

// UserReport is a snapshot of everything sentry knows about a user
// at a point in time.
type UserReport struct {
	UID            string
	Nick           string

	// Numeric ranking of feature contributions to the L3 logit,
	// sorted by absolute Contrib descending. Top N entries are the
	// "smoking guns" -- show these in the bot summary.
	Top            []FeatureContribution

	// Raw probability the classifier assigned.
	MaliceProb     float64
	Logit          float64

	// Anomalous features per L2 z-threshold.
	AnomalousZ     []anomaly.Finding
}

// Explain builds a UserReport given a current feature snapshot and
// the trained models. fm should be the numeric feature map AFTER any
// scaling (log1p) the manager applies before training -- otherwise
// the contribution math won't match what the classifier actually saw.
func Explain(uid, nick string, fm classifier.FeatureMap, clf *classifier.Model, am *anomaly.Model) UserReport {
	r := UserReport{UID: uid, Nick: nick}
	if clf != nil {
		weights := clf.Weights()
		var logit float64 = clf.Bias()
		for f, v := range fm {
			w := weights[f]
			contrib := w * v
			logit += contrib
			r.Top = append(r.Top, FeatureContribution{
				Feature: f, Value: v, Weight: w, Contrib: contrib,
			})
		}
		r.Logit = logit
		r.MaliceProb = sigmoid(logit)
	}
	if am != nil {
		// Map z-scores by feature so we can attach to Top entries.
		zMap := am.Score(fm)
		for i := range r.Top {
			r.Top[i].ZScore = zMap[r.Top[i].Feature]
		}
		r.AnomalousZ = am.Anomalous(fm)
	}
	sort.Slice(r.Top, func(i, j int) bool {
		return absF(r.Top[i].Contrib) > absF(r.Top[j].Contrib)
	})
	return r
}

// Format renders a short, plain-text summary suitable for #opers.
// Caps at the top topN contributions.
func Format(r UserReport, topN int) string {
	if topN <= 0 {
		topN = 5
	}
	var b strings.Builder
	fmt.Fprintf(&b, "sentry report on %s (uid=%s):\n", r.Nick, r.UID)
	fmt.Fprintf(&b, "  L3 probability: %.3f (logit=%.2f)\n", r.MaliceProb, r.Logit)
	if len(r.AnomalousZ) > 0 {
		fmt.Fprintf(&b, "  L2 anomalies: ")
		parts := make([]string, 0, len(r.AnomalousZ))
		for _, f := range r.AnomalousZ {
			parts = append(parts, fmt.Sprintf("%s(z=%.1f)", f.Feature, f.Z))
		}
		fmt.Fprintf(&b, "%s\n", strings.Join(parts, ", "))
	}
	if len(r.Top) > 0 {
		fmt.Fprintf(&b, "  top features:\n")
		for i, c := range r.Top {
			if i >= topN {
				break
			}
			sign := "+"
			if c.Contrib < 0 {
				sign = "-"
			}
			fmt.Fprintf(&b, "    %s%.2f  %s  (v=%.2f w=%.2f",
				sign, absF(c.Contrib), c.Feature, c.Value, c.Weight)
			if c.ZScore != 0 {
				fmt.Fprintf(&b, " z=%.1f", c.ZScore)
			}
			fmt.Fprintf(&b, ")\n")
		}
	}
	return b.String()
}

func absF(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func sigmoid(z float64) float64 {
	if z > 30 {
		return 1
	}
	if z < -30 {
		return 0
	}
	return 1.0 / (1.0 + math.Exp(-z))
}

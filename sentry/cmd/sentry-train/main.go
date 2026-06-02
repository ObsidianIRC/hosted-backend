// Command sentry-train runs the simulator against an in-process
// sentry Manager and persists the resulting L2 + L3 models to disk.
// The daemon (sentry/cmd/sentry) then loads these snapshots on boot.
//
// All training data is synthetic, local, and deterministic given a
// seed. No traffic leaves the host.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"backend/sentry"
	"backend/sentry/anomaly"
	"backend/sentry/classifier"
	"backend/sentry/heuristics"
	"backend/sentry/sim"
)

func main() {
	var (
		out      = flag.String("out", "models.json", "output snapshot path")
		passes   = flag.Int("passes", 30, "training passes over scenario suite")
		benignPerPass = flag.Int("benign-per-pass", 25, "benign instances per training pass")
		useMarkov     = flag.Bool("markov", true, "use Markov-driven benign chatter (richer training)")
		lr            = flag.Float64("lr", 0.02, "L3 SGD learning rate")
		zthresh       = flag.Float64("l2-z", 3.0, "L2 z-score threshold (saved with the model)")
		verbose       = flag.Bool("v", false, "print per-pass progress")
	)
	flag.Parse()

	log.SetFlags(0)
	log.Printf("sentry-train: %d passes, %d benign/pass, markov=%v, lr=%.3f",
		*passes, *benignPerPass, *useMarkov, *lr)

	labels := newLabelStore()
	am := anomaly.NewModel()
	am.ZThreshold = *zthresh
	clf := classifier.NewModel()
	clf.SetLearningRate(*lr)

	// Silent alert sink during training -- we don't care about
	// per-event alerts here, only the final model weights.
	mgr := sentry.NewManager(
		sentry.WithSink(silentSink{}),
		sentry.WithAnomalyModel(am),
		sentry.WithClassifier(clf, 0.7),
		sentry.WithClassifierLabeler(labels.lookup),
	)

	// Build the benign pool: cycle through all scenarios labeled
	// benign in the canonical set so the classifier sees every
	// benign shape during training.
	benignPool := []sim.Scenario{}
	if *useMarkov {
		benignPool = append(benignPool, sim.MarkovBenign)
	}
	for _, s := range sim.AllScenarios {
		if s.Label == sim.LabelBenign {
			benignPool = append(benignPool, s)
		}
	}

	startAt := time.Unix(1_700_000_000, 0)
	t0 := time.Now()
	for pass := 1; pass <= *passes; pass++ {
		for b := 0; b < *benignPerPass; b++ {
			seed := int64(pass*10000 + b)
			uid := "B-" + strconv.Itoa(pass) + "-" + strconv.Itoa(b)
			labels.set(uid, 0)
			scen := benignPool[b%len(benignPool)]
			sim.Play(mgr, scen.Generate(uid, "u"+strconv.Itoa(b),
				startAt, sim.MakeRNG(seed)))
		}
		for scenIdx, s := range sim.AllScenarios {
			if s.Label == sim.LabelBenign {
				continue
			}
			seed := int64(pass*100 + scenIdx)
			uid := "A-" + strconv.Itoa(pass) + "-" + strconv.Itoa(scenIdx)
			labels.set(uid, 1)
			sim.Play(mgr, s.Generate(uid, "a"+strconv.Itoa(scenIdx),
				startAt, sim.MakeRNG(seed)))
		}
		if *verbose && pass%5 == 0 {
			log.Printf("  pass %d/%d  steps=%d  anomaly_samples=%d",
				pass, *passes, clf.Steps(), am.Samples(anomaly.FeatMsgRate))
		}
	}
	dur := time.Since(t0)
	log.Printf("training complete: %d SGD steps, anomaly N=%d for msg_rate, %s wallclock",
		clf.Steps(), am.Samples(anomaly.FeatMsgRate), dur)

	// Dump top weights so the operator can sanity-check.
	type wp struct {
		Feature classifier.FeatureName
		Weight  float64
	}
	weights := clf.Weights()
	var ws []wp
	for f, w := range weights {
		ws = append(ws, wp{f, w})
	}
	// Quick bubble-sort by abs weight desc (no sort import).
	for i := 1; i < len(ws); i++ {
		for j := i; j > 0 && absF(ws[j-1].Weight) < absF(ws[j].Weight); j-- {
			ws[j-1], ws[j] = ws[j], ws[j-1]
		}
	}
	log.Printf("top L3 weights:")
	limit := 12
	if len(ws) < limit {
		limit = len(ws)
	}
	for i := 0; i < limit; i++ {
		log.Printf("  %+.3f  %s", ws[i].Weight, ws[i].Feature)
	}
	log.Printf("L3 bias: %+.3f", clf.Bias())

	// Persist snapshot in the same shape the daemon's loadModels reads.
	blob := struct {
		Anomaly    map[anomaly.FeatureName]anomaly.Welford `json:"anomaly"`
		Classifier classifier.Snapshot                     `json:"classifier"`
		SavedAt    int64                                   `json:"saved_at_unix_ms"`
		Trainer    map[string]interface{}                  `json:"trainer"`
	}{
		Anomaly:    am.Snapshot(),
		Classifier: clf.Snapshot(),
		SavedAt:    time.Now().UnixMilli(),
		Trainer: map[string]interface{}{
			"passes":         *passes,
			"benign_per_pass": *benignPerPass,
			"markov":         *useMarkov,
			"lr":             *lr,
			"l2_z":           *zthresh,
			"wall_seconds":   dur.Seconds(),
		},
	}
	data, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		log.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	log.Printf("wrote %s (%d bytes)", *out, len(data))
	_ = fmt.Sprintf
}

func absF(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

type silentSink struct{}

func (silentSink) Emit([]heuristics.Alert) {}

type labelStore struct {
	m map[string]float64
}

func newLabelStore() *labelStore { return &labelStore{m: map[string]float64{}} }
func (l *labelStore) set(uid string, v float64) { l.m[uid] = v }
func (l *labelStore) lookup(uid string) (float64, bool) {
	v, ok := l.m[uid]
	return v, ok
}

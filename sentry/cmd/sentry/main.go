// Command sentry runs the training side of the detection pipeline.
//
// Detection + blocking is done in-process inside obbyircd's sentinel
// module. This daemon does NOT take moderation actions. Its jobs:
//
//   - consume events from sentinel.c over a Unix socket
//   - update L2 anomaly baselines (Welford) and L3 weights (SGD)
//   - persist labelled feedback rows + model snapshots
//   - expose an admin HTTP API + bot for opers to query and label
//
// The trained models.json lives in the state directory; sentinel
// reloads it on rehash.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"backend/sentry"
	"backend/sentry/adminapi"
	"backend/sentry/anomaly"
	"backend/sentry/classifier"
	"backend/sentry/explain"
	"backend/sentry/feedback"
	"backend/sentry/heuristics"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	var (
		socketPath  = flag.String("socket", "/run/obby/sentry.sock", "Unix socket sentinel.c connects to")
		stateDir    = flag.String("state", "/var/lib/obby/sentry", "directory for model snapshots + feedback DB")
		zThreshold  = flag.Float64("l2-z", 3.0, "L2 z-score threshold (emit-only)")
		mlThreshold = flag.Float64("l3-p", 0.7, "L3 probability threshold (emit-only)")
		saveEvery   = flag.Duration("save-every", 5*time.Minute, "interval for model snapshot persistence")
		adminAddr   = flag.String("admin-addr", "127.0.0.1:9601", "localhost-only HTTP admin API (empty disables)")
	)
	flag.Parse()

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		log.Fatalf("mkdir state dir: %v", err)
	}
	modelPath := filepath.Join(*stateDir, "models.json")
	dbPath := filepath.Join(*stateDir, "feedback.db")

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("open feedback db: %v", err)
	}
	store, err := feedback.Open(db)
	if err != nil {
		log.Fatalf("init feedback store: %v", err)
	}
	defer store.Close()

	am := anomaly.NewModel()
	am.ZThreshold = *zThreshold
	clf := classifier.NewModel()
	if err := loadModels(modelPath, am, clf); err != nil {
		log.Printf("load models: %v (starting fresh)", err)
	}

	var api *adminapi.Server
	if *adminAddr != "" {
		api = adminapi.New(*adminAddr, nil)
	}
	mgr := sentry.NewManager(
		sentry.WithSink(multiSink{&logAlertSink{}, api}),
		sentry.WithAnomalyModel(am),
		sentry.WithClassifier(clf, *mlThreshold),
		sentry.WithFeedbackStore(store),
	)
	if api != nil {
		api.Manager = &mgrAdapter{m: mgr}
	}

	ctx, cancel := signalContext()
	defer cancel()

	go mgr.Run(ctx)
	if api != nil {
		if err := api.Start(ctx); err != nil {
			log.Fatalf("admin api: %v", err)
		}
	}

	srv := sentry.NewSocketServer(*socketPath, mgr)
	if err := srv.Listen(); err != nil {
		log.Fatalf("listen socket: %v", err)
	}
	go func() {
		if err := srv.Run(ctx); err != nil {
			log.Printf("socket server stopped: %v", err)
		}
	}()

	go periodicSave(ctx, modelPath, am, clf, *saveEvery)

	<-ctx.Done()
	log.Printf("[sentry] shutting down")
	if err := saveModels(modelPath, am, clf); err != nil {
		log.Printf("final save: %v", err)
	}
	srv.Stop()
	mgr.Stop()
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

type modelsBlob struct {
	Anomaly    map[anomaly.FeatureName]anomaly.Welford `json:"anomaly"`
	Classifier classifier.Snapshot                     `json:"classifier"`
	SavedAt    int64                                   `json:"saved_at_unix_ms"`
}

func saveModels(path string, am *anomaly.Model, clf *classifier.Model) error {
	blob := modelsBlob{
		Anomaly:    am.Snapshot(),
		Classifier: clf.Snapshot(),
		SavedAt:    time.Now().UnixMilli(),
	}
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(blob, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadModels(path string, am *anomaly.Model, clf *classifier.Model) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var blob modelsBlob
	if err := json.Unmarshal(data, &blob); err != nil {
		return err
	}
	if blob.Anomaly != nil {
		am.LoadSnapshot(blob.Anomaly)
	}
	clf.LoadSnapshot(blob.Classifier)
	return nil
}

func periodicSave(ctx context.Context, path string, am *anomaly.Model, clf *classifier.Model, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := saveModels(path, am, clf); err != nil {
				log.Printf("save models: %v", err)
			}
		}
	}
}

type logAlertSink struct{}

func (logAlertSink) Emit(alerts []heuristics.Alert) {
	for _, a := range alerts {
		log.Printf("[alert] uid=%s nick=%s kind=%s conf=%.3f evidence=%q",
			a.UID, a.Nick, a.Kind, a.Confidence, a.Evidence)
	}
}

type multiSink []sentry.AlertSink

func (m multiSink) Emit(alerts []heuristics.Alert) {
	for _, s := range m {
		if s == nil {
			continue
		}
		s.Emit(alerts)
	}
}

type mgrAdapter struct{ m *sentry.Manager }

func (a *mgrAdapter) Explain(uid string) explain.UserReport          { return a.m.Explain(uid) }
func (a *mgrAdapter) RecordFeedback(l feedback.Label) (int64, error) { return a.m.RecordFeedback(l) }
func (a *mgrAdapter) UIDByNick(nick string) string                   { return a.m.UIDByNick(nick) }
func (a *mgrAdapter) Stats() adminapi.ManagerStats {
	s := a.m.Stats()
	return adminapi.ManagerStats{
		TrackedUsers: s.TrackedUsers,
		EventsTotal:  s.EventsTotal,
		AlertsTotal:  s.AlertsTotal,
		RuleNames:    s.RuleNames,
	}
}

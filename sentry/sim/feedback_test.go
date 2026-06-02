package sim_test

import (
	"database/sql"
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/anomaly"
	"backend/sentry/classifier"
	"backend/sentry/events"
	"backend/sentry/feedback"

	_ "github.com/mattn/go-sqlite3"
)

func openFeedback(t *testing.T) *feedback.Store {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	s, err := feedback.Open(db)
	if err != nil {
		t.Fatalf("feedback.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestOperFeedbackTrainsClassifier: an oper marks a user
// VerdictBad; the classifier must record an extra SGD step AND the
// feedback row must persist.
func TestOperFeedbackTrainsClassifier(t *testing.T) {
	store := openFeedback(t)
	clf := classifier.NewModel()
	am := anomaly.NewModel()

	m := sentry.NewManager(
		sentry.WithAnomalyModel(am),
		sentry.WithClassifier(clf, 0.7),
		sentry.WithFeedbackStore(store),
	)

	// Get a user into the system so RecordFeedback can build a
	// feature snapshot.
	now := time.Now()
	m.Observe(&events.Event{
		Kind: events.EventConnect, UID: "u1", Nick: "bob",
		Time: now.UnixMilli(),
	})
	m.Observe(&events.Event{
		Kind: events.EventChanMsg, UID: "u1", Nick: "bob",
		Channel: "#x", Text: "hi", Time: now.UnixMilli() + 1000,
	})

	stepsBefore := clf.Steps()
	id, err := m.RecordFeedback(feedback.Label{
		UID: "u1", Nick: "bob", Verdict: feedback.VerdictBad,
		Source: "oper:valware", AlertKind: "flood",
		Evidence: "yes obvious spam",
	})
	if err != nil {
		t.Fatalf("RecordFeedback: %v", err)
	}
	if id == 0 {
		t.Fatalf("expected non-zero feedback id")
	}
	if clf.Steps() != stepsBefore+1 {
		t.Fatalf("classifier did not train: steps before=%d after=%d",
			stepsBefore, clf.Steps())
	}
	rows, err := store.Recent(5)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(rows) != 1 || rows[0].Verdict != feedback.VerdictBad {
		t.Fatalf("feedback row missing or wrong: %+v", rows)
	}
}

// TestIgnoreVerdictDoesNotTrain: VerdictIgnore must NOT update the
// classifier (just record the disposition).
func TestIgnoreVerdictDoesNotTrain(t *testing.T) {
	store := openFeedback(t)
	clf := classifier.NewModel()
	m := sentry.NewManager(
		sentry.WithClassifier(clf, 0.7),
		sentry.WithFeedbackStore(store),
	)
	m.Observe(&events.Event{
		Kind: events.EventConnect, UID: "u2", Nick: "alice",
		Time: time.Now().UnixMilli(),
	})
	before := clf.Steps()
	if _, err := m.RecordFeedback(feedback.Label{
		UID: "u2", Verdict: feedback.VerdictIgnore,
	}); err != nil {
		t.Fatalf("RecordFeedback: %v", err)
	}
	if clf.Steps() != before {
		t.Fatalf("VerdictIgnore should not train; steps before=%d after=%d",
			before, clf.Steps())
	}
}

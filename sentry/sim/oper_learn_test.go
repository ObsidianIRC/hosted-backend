package sim_test

import (
	"database/sql"
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/classifier"
	"backend/sentry/events"
	"backend/sentry/feedback"

	_ "github.com/mattn/go-sqlite3"
)

// TestOperKillTrainsClassifier: a /KILL event from an oper must (a)
// persist a feedback row tagged oper:<nick> and (b) advance the L3
// SGD step counter against the target's current feature vector.
func TestOperKillTrainsClassifier(t *testing.T) {
	db, _ := sql.Open("sqlite3", ":memory:")
	store, err := feedback.Open(db)
	if err != nil {
		t.Fatalf("feedback.Open: %v", err)
	}
	defer store.Close()

	clf := classifier.NewModel()
	m := sentry.NewManager(
		sentry.WithClassifier(clf, 0.7),
		sentry.WithFeedbackStore(store),
	)

	now := time.Unix(1_700_000_000, 0)
	// User connects + sends some messages so they have a feature
	// vector worth training on.
	m.Observe(&events.Event{
		Kind: events.EventConnect, UID: "u1", Nick: "spammer",
		Time: now.UnixMilli(),
	})
	for i := 0; i < 5; i++ {
		m.Observe(&events.Event{
			Kind: events.EventChanMsg, UID: "u1", Nick: "spammer",
			Channel: "#x", Text: "buy crypto https://scam.invalid/win",
			Time: now.Add(time.Duration(i) * time.Second).UnixMilli(),
		})
	}

	stepsBefore := clf.Steps()

	// Oper KILLs them.
	m.Observe(&events.Event{
		Kind: events.EventOperKill,
		UID:  "u1", Nick: "spammer",
		Oper:   "valware",
		Reason: "obvious spam",
		Time:   now.Add(10 * time.Second).UnixMilli(),
	})

	if clf.Steps() != stepsBefore+1 {
		t.Fatalf("oper kill did not advance SGD: before=%d after=%d",
			stepsBefore, clf.Steps())
	}
	rows, err := store.Recent(5)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 feedback row, got %d", len(rows))
	}
	if rows[0].Source != "oper:valware" || rows[0].Verdict != feedback.VerdictBad ||
		rows[0].AlertKind != "oper_kill" {
		t.Fatalf("wrong feedback row: %+v", rows[0])
	}
}

// TestOperKickWithoutClassifierStillRecords: if no classifier is
// wired the feedback row must still land (audit trail).
func TestOperKickWithoutClassifierStillRecords(t *testing.T) {
	db, _ := sql.Open("sqlite3", ":memory:")
	store, err := feedback.Open(db)
	if err != nil {
		t.Fatalf("feedback.Open: %v", err)
	}
	defer store.Close()

	m := sentry.NewManager(sentry.WithFeedbackStore(store))
	now := time.Unix(1_700_010_000, 0)
	m.Observe(&events.Event{
		Kind: events.EventConnect, UID: "u2", Nick: "rude",
		Time: now.UnixMilli(),
	})
	m.Observe(&events.Event{
		Kind: events.EventOperKick,
		UID:  "u2", Nick: "rude",
		Oper: "valware", Channel: "#general",
		Reason: "harassment", Time: now.Add(time.Second).UnixMilli(),
	})
	rows, _ := store.Recent(5)
	if len(rows) != 1 || rows[0].AlertKind != "oper_kick" {
		t.Fatalf("oper kick not recorded: %+v", rows)
	}
}

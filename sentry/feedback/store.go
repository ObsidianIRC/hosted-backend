// Package feedback persists operator-supplied ground-truth labels.
// Opers tag a flagged user as confirmed-bad / confirmed-good via the
// Orca bot UI; each tag becomes a Label row and (when applied to a
// running pipeline) feeds the L3 classifier as an authoritative SGD
// update so the model learns from real moderator judgment.
package feedback

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// Verdict is the binary moderator decision. Mapped to L3 labels:
// confirmed-bad -> 1.0, confirmed-good -> 0.0, ignored -> no SGD update.
type Verdict int

const (
	VerdictUnknown Verdict = iota
	VerdictBad             // confirmed malicious (action was warranted)
	VerdictGood            // confirmed benign (false positive)
	VerdictIgnore          // operator dismissed without judgment
)

func (v Verdict) String() string {
	switch v {
	case VerdictBad:
		return "bad"
	case VerdictGood:
		return "good"
	case VerdictIgnore:
		return "ignore"
	default:
		return "unknown"
	}
}

// Label is one row in the feedback table.
type Label struct {
	ID        int64
	UID       string  // sentry user UID
	Nick      string  // nick at time of judgement (display only)
	Verdict   Verdict
	Source    string  // "oper:<nick>" or "scenario" or "auto"
	AlertKind string  // the alert kind that triggered the oper prompt
	Evidence  string  // free-text reason / oper comment
	At        time.Time
}

// Store wraps a SQLite handle and exposes the minimal API the rest of
// sentry needs. All methods are safe for concurrent use; the sql.DB
// pool itself is thread-safe and we add an RWMutex only around batched
// reads where we want a consistent snapshot.
type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

// Open creates or opens a Store at path. Caller is responsible for
// closing via Close. The schema is created on first open.
func Open(db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close releases the underlying handle.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS sentry_feedback (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	uid          TEXT    NOT NULL,
	nick         TEXT    NOT NULL DEFAULT '',
	verdict      INTEGER NOT NULL,
	source       TEXT    NOT NULL DEFAULT '',
	alert_kind   TEXT    NOT NULL DEFAULT '',
	evidence     TEXT    NOT NULL DEFAULT '',
	at_unix_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sentry_feedback_uid     ON sentry_feedback(uid);
CREATE INDEX IF NOT EXISTS idx_sentry_feedback_at      ON sentry_feedback(at_unix_ms);
CREATE INDEX IF NOT EXISTS idx_sentry_feedback_verdict ON sentry_feedback(verdict);
`)
	return err
}

// Record persists one feedback row. Returns the assigned ID.
func (s *Store) Record(l Label) (int64, error) {
	if l.At.IsZero() {
		l.At = time.Now()
	}
	res, err := s.db.Exec(`
INSERT INTO sentry_feedback (uid, nick, verdict, source, alert_kind, evidence, at_unix_ms)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		l.UID, l.Nick, int(l.Verdict), l.Source, l.AlertKind, l.Evidence, l.At.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Recent returns the most recent N feedback rows, newest first.
func (s *Store) Recent(n int) ([]Label, error) {
	if n <= 0 {
		n = 50
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
SELECT id, uid, nick, verdict, source, alert_kind, evidence, at_unix_ms
FROM sentry_feedback ORDER BY at_unix_ms DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Label
	for rows.Next() {
		var l Label
		var v int
		var ms int64
		if err := rows.Scan(&l.ID, &l.UID, &l.Nick, &v, &l.Source, &l.AlertKind, &l.Evidence, &ms); err != nil {
			return nil, err
		}
		l.Verdict = Verdict(v)
		l.At = time.UnixMilli(ms)
		out = append(out, l)
	}
	return out, rows.Err()
}

// CountByVerdict returns a {bad, good, ignore} histogram across all rows.
// Useful for the explainability dashboard.
func (s *Store) CountByVerdict() (bad, good, ignore int, err error) {
	rows, err := s.db.Query(`
SELECT verdict, COUNT(*) FROM sentry_feedback GROUP BY verdict`)
	if err != nil {
		return 0, 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var v, n int
		if err := rows.Scan(&v, &n); err != nil {
			return 0, 0, 0, err
		}
		switch Verdict(v) {
		case VerdictBad:
			bad = n
		case VerdictGood:
			good = n
		case VerdictIgnore:
			ignore = n
		}
	}
	return bad, good, ignore, rows.Err()
}

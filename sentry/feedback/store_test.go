package feedback

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func openMem(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	s, err := Open(db)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestRecordAndRecent(t *testing.T) {
	s := openMem(t)
	defer s.Close()

	at := time.Unix(1_700_000_000, 0)
	id, err := s.Record(Label{
		UID: "u1", Nick: "n1", Verdict: VerdictBad,
		Source: "oper:valware", AlertKind: "flood",
		Evidence: "obvious spam", At: at,
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if id == 0 {
		t.Fatalf("expected non-zero id")
	}

	rows, err := s.Recent(10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	if rows[0].UID != "u1" || rows[0].Verdict != VerdictBad {
		t.Fatalf("bad row: %+v", rows[0])
	}
}

func TestCountByVerdict(t *testing.T) {
	s := openMem(t)
	defer s.Close()

	for _, v := range []Verdict{VerdictBad, VerdictBad, VerdictBad, VerdictGood, VerdictIgnore, VerdictIgnore} {
		if _, err := s.Record(Label{UID: "u", Verdict: v}); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	bad, good, ignore, err := s.CountByVerdict()
	if err != nil {
		t.Fatalf("CountByVerdict: %v", err)
	}
	if bad != 3 || good != 1 || ignore != 2 {
		t.Fatalf("got bad=%d good=%d ignore=%d, want 3/1/2", bad, good, ignore)
	}
}

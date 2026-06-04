package orca

import (
	"database/sql"
	"encoding/json"
	"log"
	"os"
	"sync"
	"time"
)

const orcaLogSchema = `
CREATE TABLE IF NOT EXISTS orca_log (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ts          TEXT NOT NULL,
	conv_key    TEXT NOT NULL,
	role        TEXT NOT NULL,
	nick        TEXT,
	account     TEXT,
	msgid       TEXT,
	content     TEXT,
	tool_calls  TEXT,
	tool_name   TEXT,
	tool_call_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_orca_log_conv_ts ON orca_log(conv_key, ts);
CREATE INDEX IF NOT EXISTS idx_orca_log_nick    ON orca_log(nick);

CREATE TABLE IF NOT EXISTS orca_actions (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	ts          TEXT NOT NULL,
	wid         TEXT NOT NULL,
	action      TEXT NOT NULL,
	target      TEXT,
	from_nick   TEXT,
	content     TEXT
);
`

type Logger struct {
	mu sync.Mutex
	db *sql.DB
}

// OpenLogger opens (and migrates) the orca sqlite log. Falls back to a
// no-op logger if the path is empty or sqlite can't open it -- so the
// rest of orca still runs.
func OpenLogger(path string) *Logger {
	if path == "" {
		path = envOr("ORCA_LOG_DB", "orca_log.db")
	}
	db, err := openSQLite(path)
	if err != nil {
		log.Printf("[orca] log: open %s: %v (continuing without persistent log)", path, err)
		return &Logger{}
	}
	if _, err := db.Exec(orcaLogSchema); err != nil {
		log.Printf("[orca] log: migrate: %v (continuing without persistent log)", err)
		_ = db.Close()
		return &Logger{}
	}
	return &Logger{db: db}
}

func (l *Logger) Close() {
	if l == nil || l.db == nil {
		return
	}
	_ = l.db.Close()
}

func (l *Logger) AppendTurn(conv ConvKey, t ConvTurn) {
	if l == nil || l.db == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var toolCallsJSON string
	if len(t.ToolCalls) > 0 {
		b, _ := json.Marshal(t.ToolCalls)
		toolCallsJSON = string(b)
	}
	_, err := l.db.Exec(`
		INSERT INTO orca_log
		(ts, conv_key, role, nick, account, msgid, content, tool_calls, tool_name, tool_call_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		t.Time.UTC().Format(time.RFC3339Nano),
		conv.String(),
		string(t.Role),
		t.Nick,
		t.Account,
		t.Msgid,
		t.Content,
		toolCallsJSON,
		t.ToolName,
		t.ToolCall.ID,
	)
	if err != nil {
		log.Printf("[orca] log: append turn: %v", err)
	}
}

func (l *Logger) AppendAction(wid, action, target, fromNick, content string) {
	if l == nil || l.db == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.db.Exec(`
		INSERT INTO orca_actions
		(ts, wid, action, target, from_nick, content)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		time.Now().UTC().Format(time.RFC3339Nano),
		wid, action, target, fromNick, content,
	)
	if err != nil {
		log.Printf("[orca] log: append action: %v", err)
	}
}

// openSQLite is split out so the import driver lives in one place;
// production wires in mattn/go-sqlite3 (already pulled in by db.go).
func openSQLite(path string) (*sql.DB, error) {
	_ = os.MkdirAll(parentDir(path), 0o755)
	db, err := sql.Open("sqlite3", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

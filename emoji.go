// Custom-emoji pack endpoints implementing the server-side bits of
// IRCv3 draft/custom-emoji.
//
// The IRCd advertises `draft/EMOJI=https://<this-host>/emoji/pack.json`
// in ISUPPORT, and clients fetch the pack JSON from there.  Packs are
// authored via the admin endpoints below by IRC operators.
//
// Channel-scoped packs (the `draft/emoji` channel METADATA case) are
// supported by storing them with scope='channel' and channel_name set;
// they are served at /emoji/channel/{channel}.json.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// emojiPack mirrors the on-the-wire shape defined by the spec.
// JSON fields are kept exactly as the spec requires.
type emojiPack struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Authors     []string           `json:"authors,omitempty"`
	Homepage    string             `json:"homepage,omitempty"`
	Required    []string           `json:"required,omitempty"`
	Emoji       map[string]emojiEntry `json:"emoji"`
}

type emojiEntry struct {
	URL string `json:"url"`
	Alt string `json:"alt,omitempty"`
}

// loadPacks builds the JSON-shaped pack list from the DB.  Filter
// determines which packs are returned -- "server" for the network
// pack document, "channel:#name" for a single channel's document.
func loadPacks(filter string) ([]emojiPack, error) {
	const q = `
		SELECT id, pack_id, name, description, authors, homepage, required
		  FROM emoji_packs
		 WHERE (? = 'server' AND scope = 'server')
		    OR (? LIKE 'channel:%' AND scope = 'channel'
		        AND lower(channel_name) = lower(substr(?, 9)))
		 ORDER BY pack_id`

	rows, err := db.Query(q, filter, filter, filter)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []emojiPack{}
	type packRow struct {
		dbID     int64
		packID   string
		name     string
		desc     string
		authors  string
		homepage string
		required string
	}
	var packs []packRow
	for rows.Next() {
		var p packRow
		if err := rows.Scan(&p.dbID, &p.packID, &p.name, &p.desc,
			&p.authors, &p.homepage, &p.required); err != nil {
			return nil, err
		}
		packs = append(packs, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, p := range packs {
		pack := emojiPack{
			ID:          p.packID,
			Name:        p.name,
			Description: p.desc,
			Homepage:    p.homepage,
			Emoji:       map[string]emojiEntry{},
		}
		if p.authors != "" {
			_ = json.Unmarshal([]byte(p.authors), &pack.Authors)
		}
		if p.required != "" {
			_ = json.Unmarshal([]byte(p.required), &pack.Required)
		}

		eRows, err := db.Query(
			"SELECT shortcode, url, alt FROM emojis WHERE pack_id = ?",
			p.dbID)
		if err != nil {
			return nil, err
		}
		for eRows.Next() {
			var sc, url, alt string
			if err := eRows.Scan(&sc, &url, &alt); err != nil {
				eRows.Close()
				return nil, err
			}
			pack.Emoji[sc] = emojiEntry{URL: url, Alt: alt}
		}
		eRows.Close()

		// Spec requires at least one emoji per pack -- skip empty
		// packs from the public document so we never emit an invalid
		// JSON structure.
		if len(pack.Emoji) > 0 {
			out = append(out, pack)
		}
	}
	return out, nil
}

// GET /emoji/pack.json -- the network-wide pack document.  Public.
func handleEmojiPack(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=60")
	packs, err := loadPacks("server")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if packs == nil {
		packs = []emojiPack{}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(packs)
}

// GET /emoji/channel/{channel}.json -- per-channel pack document.
func handleEmojiChannelPack(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=30")
	channel := mux.Vars(r)["channel"]
	if channel == "" {
		http.Error(w, "channel required", http.StatusBadRequest)
		return
	}
	packs, err := loadPacks("channel:" + channel)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if packs == nil {
		packs = []emojiPack{}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(packs)
}

// --- Admin endpoints (IRCop only) ------------------------------------------

type createPackBody struct {
	PackID      string   `json:"pack_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Authors     []string `json:"authors"`
	Homepage    string   `json:"homepage"`
	Required    []string `json:"required"`
	Scope       string   `json:"scope"`        // "server" or "channel"
	ChannelName string   `json:"channel_name"` // required iff scope=="channel"
}

func handleCreatePack(w http.ResponseWriter, r *http.Request) {
	var body createPackBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if body.PackID == "" || body.Name == "" {
		http.Error(w, "pack_id and name required", http.StatusBadRequest)
		return
	}
	if body.Scope == "" {
		body.Scope = "server"
	}
	if body.Scope != "server" && body.Scope != "channel" {
		http.Error(w, "scope must be server or channel", http.StatusBadRequest)
		return
	}
	if body.Scope == "channel" && body.ChannelName == "" {
		http.Error(w, "channel_name required when scope=channel", http.StatusBadRequest)
		return
	}

	authorsJSON, _ := json.Marshal(body.Authors)
	requiredJSON, _ := json.Marshal(body.Required)

	_, err := db.Exec(`
		INSERT INTO emoji_packs
			(pack_id, name, description, authors, homepage,
			 required, scope, channel_name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		body.PackID, body.Name, body.Description, string(authorsJSON),
		body.Homepage, string(requiredJSON), body.Scope, body.ChannelName)
	if err != nil {
		// Probably duplicate pack_id.
		http.Error(w, fmt.Sprintf("create pack: %v", err), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"pack_id": body.PackID})
}

type addEmojiBody struct {
	Shortcode string `json:"shortcode"`
	URL       string `json:"url"`
	Alt       string `json:"alt"`
}

// validShortcode returns true for spec-compliant shortcodes (no
// control / format / surrogate / separator chars, no '/' or ':').
// We keep this simple: ASCII letters, digits, dashes, underscores
// and dots.  More permissive checks can be added if a deployment
// needs them.
func validShortcode(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

func handleAddEmoji(w http.ResponseWriter, r *http.Request) {
	packID := mux.Vars(r)["packId"]
	var body addEmojiBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if !validShortcode(body.Shortcode) {
		http.Error(w, "shortcode must match [A-Za-z0-9._-]+", http.StatusBadRequest)
		return
	}
	if !strings.HasPrefix(body.URL, "https://") &&
		!strings.HasPrefix(body.URL, "http://") &&
		!strings.HasPrefix(body.URL, "data:") {
		http.Error(w, "url must be http(s) or data:", http.StatusBadRequest)
		return
	}

	var dbPackID int64
	err := db.QueryRow(
		"SELECT id FROM emoji_packs WHERE pack_id = ?", packID,
	).Scan(&dbPackID)
	if err != nil {
		http.Error(w, "pack not found", http.StatusNotFound)
		return
	}

	_, err = db.Exec(`
		INSERT INTO emojis (pack_id, shortcode, url, alt)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(pack_id, shortcode) DO UPDATE SET
		    url = excluded.url, alt = excluded.alt`,
		dbPackID, body.Shortcode, body.URL, body.Alt)
	if err != nil {
		http.Error(w, fmt.Sprintf("add emoji: %v", err), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func handleDeleteEmoji(w http.ResponseWriter, r *http.Request) {
	packID := mux.Vars(r)["packId"]
	shortcode := mux.Vars(r)["shortcode"]

	res, err := db.Exec(`
		DELETE FROM emojis
		 WHERE pack_id = (SELECT id FROM emoji_packs WHERE pack_id = ?)
		   AND shortcode = ?`,
		packID, shortcode)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func handleDeletePack(w http.ResponseWriter, r *http.Request) {
	packID := mux.Vars(r)["packId"]
	res, err := db.Exec("DELETE FROM emoji_packs WHERE pack_id = ?", packID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /emoji/admin/packs -- IRCop-only: list every pack including
// empties (for the admin UI).
func handleListPacks(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT pack_id, name, description, scope, channel_name, updated_at
		  FROM emoji_packs ORDER BY pack_id`)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type entry struct {
		PackID      string `json:"pack_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Scope       string `json:"scope"`
		ChannelName string `json:"channel_name,omitempty"`
		UpdatedAt   string `json:"updated_at"`
		EmojiCount  int    `json:"emoji_count"`
	}
	var out []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.PackID, &e.Name, &e.Description,
			&e.Scope, &e.ChannelName, &e.UpdatedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_ = db.QueryRow(`
			SELECT COUNT(*) FROM emojis WHERE pack_id =
				(SELECT id FROM emoji_packs WHERE pack_id = ?)`,
			e.PackID).Scan(&e.EmojiCount)
		out = append(out, e)
	}
	if out == nil {
		out = []entry{}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

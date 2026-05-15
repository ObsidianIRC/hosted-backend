package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	unrealircd "github.com/ObsidianIRC/unrealircd-rpc-golang"
)

// Global var for connection
var ircConn *unrealircd.Connection

// ircMu guards re-creating ircConn during a reconnect.  The
// underlying Query() already serialises its own writes, but we need
// our own lock to keep two callers from racing on the pointer swap.
var ircMu sync.Mutex

// InitIRCConn initializes the IRC connection
func InitIRCConn() error {
	wsURL := os.Getenv("UNREALIRCD_WS_URL")
	if wsURL == "" {
		wsURL = "wss://127.0.0.1:8600/"
	}
	username := os.Getenv("UNREALIRCD_API_USERNAME")
	if username == "" {
		username = "adminpanel"
	}
	password := os.Getenv("UNREALIRCD_API_PASSWORD")
	if password == "" {
		password = "password"
	}
	apiLogin := username + ":" + password

	conn, err := unrealircd.NewConnection(wsURL, apiLogin, &unrealircd.Options{
		TLSVerify: false,
	})
	if err != nil {
		return err
	}
	ircConn = conn
	return nil
}

// ircQuery runs a JSON-RPC method against ircConn and transparently
// reconnects once if the underlying websocket has been torn down
// (most commonly because the IRCd restarted or rehashed and dropped
// idle peers). The RPC library has no built-in retry, so a stale
// pointer will otherwise fail every subsequent call with "broken
// pipe" / "use of closed network connection".
func ircQuery(method string, params map[string]interface{}) (interface{}, error) {
	ircMu.Lock()
	defer ircMu.Unlock()

	if ircConn == nil {
		if err := InitIRCConn(); err != nil {
			return nil, fmt.Errorf("ircd RPC unavailable: %w", err)
		}
	}

	raw, err := ircConn.Query(method, params, false)
	if err == nil {
		return raw, nil
	}
	if !isIRCConnError(err) {
		return nil, err
	}

	// Connection looks dead — reconnect and retry once.  If the
	// reconnect itself fails we surface the original error
	// alongside, otherwise callers get a misleading "connection
	// refused" when the real problem was something else.
	if rerr := InitIRCConn(); rerr != nil {
		return nil, fmt.Errorf("ircd RPC reconnect failed: %w (original error: %v)", rerr, err)
	}
	return ircConn.Query(method, params, false)
}

func isIRCConnError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, marker := range []string{
		"broken pipe",
		"use of closed network connection",
		"connection reset",
		"websocket: close",
		"EOF",
		"i/o timeout",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

// IRC handlers
func handleIRCUsers(w http.ResponseWriter, r *http.Request) {
	if ircConn == nil {
		http.Error(w, "IRC connection not available", http.StatusInternalServerError)
		return
	}
	result, err := ircConn.User().GetAll(2)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleIRCChannels(w http.ResponseWriter, r *http.Request) {
	if ircConn == nil {
		http.Error(w, "IRC connection not available", http.StatusInternalServerError)
		return
	}
	result, err := ircConn.Channel().GetAll(1)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleIRCBans(w http.ResponseWriter, r *http.Request) {
	if ircConn == nil {
		http.Error(w, "IRC connection not available", http.StatusInternalServerError)
		return
	}
	result, err := ircConn.ServerBan().GetAll()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleIRCStats(w http.ResponseWriter, r *http.Request) {
	if ircConn == nil {
		http.Error(w, "IRC connection not available", http.StatusInternalServerError)
		return
	}
	result, err := ircConn.Query("stats.get", map[string]interface{}{"object_detail_level": 2}, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleIRCServerUptime(w http.ResponseWriter, r *http.Request) {
	if ircConn == nil {
		http.Error(w, "IRC connection not available", http.StatusInternalServerError)
		return
	}
	server := r.URL.Query().Get("server")
	if server == "" {
		server = "irc.example.com" // default
	}
	result, err := ircConn.Query("server.get", map[string]interface{}{"server": server}, false)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
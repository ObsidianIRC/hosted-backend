package main

import (
	"encoding/json"
	"net/http"
	"os"

	unrealircd "github.com/ObsidianIRC/unrealircd-rpc-golang"
)

// Global var for connection
var ircConn *unrealircd.Connection

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
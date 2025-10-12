package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
)

// RegisterChannelRequest represents channel registration request
type RegisterChannelRequest struct {
	ChannelName  string `json:"channel_name"`
	ChannelTopic string `json:"channel_topic"`
	Modes        string `json:"modes"`
}

// UpdateChannelRequest represents channel update request
type UpdateChannelRequest struct {
	ChannelTopic *string `json:"channel_topic,omitempty"`
	Modes        *string `json:"modes,omitempty"`
}

// PermissionRequest represents permission request
type PermissionRequest struct {
	UserID      int    `json:"user_id"`
	Permissions string `json:"permissions"`
}

// handleRegisterChannel handles channel registration
func handleRegisterChannel(w http.ResponseWriter, r *http.Request) {
	var req RegisterChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "INVALID_REQUEST", "Invalid JSON", http.StatusBadRequest)
		return
	}

	result, err := db.Exec(
		"INSERT INTO channels (channel_name, channel_topic, modes) VALUES (?, ?, ?)",
		req.ChannelName, req.ChannelTopic, req.Modes,
	)
	if err != nil {
		sendError(w, "REGISTRATION_FAILED", "Channel registration failed: "+err.Error(), http.StatusConflict)
		return
	}

	channelID, _ := result.LastInsertId()

	sendSuccess(w, "CHANNEL_CREATED", "Channel created successfully", map[string]interface{}{
		"channel_id": channelID,
	})
}

// handleUpdateChannel handles channel updates
func handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelIDStr := vars["id"]
	channelID, err := strconv.Atoi(channelIDStr)
	if err != nil {
		sendError(w, "INVALID_ID", "Invalid channel ID", http.StatusBadRequest)
		return
	}

	var req UpdateChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "INVALID_REQUEST", "Invalid JSON", http.StatusBadRequest)
		return
	}

	setParts := []string{}
	args := []interface{}{}

	if req.ChannelTopic != nil {
		setParts = append(setParts, "channel_topic = ?")
		args = append(args, *req.ChannelTopic)
	}

	if req.Modes != nil {
		setParts = append(setParts, "modes = ?")
		args = append(args, *req.Modes)
	}

	if len(setParts) == 0 {
		sendError(w, "NO_UPDATES", "No fields to update", http.StatusBadRequest)
		return
	}

	query := "UPDATE channels SET " + strings.Join(setParts, ", ") + " WHERE id = ?"
	args = append(args, channelID)

	result, err := db.Exec(query, args...)
	if err != nil {
		sendError(w, "UPDATE_FAILED", "Failed to update channel", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		sendError(w, "CHANNEL_NOT_FOUND", "Channel not found", http.StatusNotFound)
		return
	}

	sendSuccess(w, "CHANNEL_UPDATED", "Channel updated successfully", nil)
}

// handleGetChannel handles getting channel info
func handleGetChannel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelIDStr := vars["id"]
	channelID, err := strconv.Atoi(channelIDStr)
	if err != nil {
		sendError(w, "INVALID_ID", "Invalid channel ID", http.StatusBadRequest)
		return
	}

	var channel Channel
	err = db.QueryRow(
		"SELECT id, channel_name, channel_topic, modes FROM channels WHERE id = ?",
		channelID,
	).Scan(&channel.ID, &channel.ChannelName, &channel.ChannelTopic, &channel.Modes)

	if err != nil {
		sendError(w, "CHANNEL_NOT_FOUND", "Channel not found", http.StatusNotFound)
		return
	}

	sendSuccess(w, "CHANNEL_RETRIEVED", "Channel retrieved successfully", channel)
}

// handleSetChannelMetadata handles setting channel metadata
func handleSetChannelMetadata(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelIDStr := vars["id"]
	channelID, err := strconv.Atoi(channelIDStr)
	if err != nil {
		sendError(w, "INVALID_ID", "Invalid channel ID", http.StatusBadRequest)
		return
	}

	var req MetadataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "INVALID_REQUEST", "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err = db.Exec(
		"INSERT OR REPLACE INTO channel_metadata (channel_id, key, value) VALUES (?, ?, ?)",
		channelID, req.Key, req.Value,
	)
	if err != nil {
		sendError(w, "METADATA_ERROR", "Failed to set metadata", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, "METADATA_SET", "Metadata set successfully", nil)
}

// handleSetChannelPermissions handles setting channel permissions
func handleSetChannelPermissions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	channelIDStr := vars["id"]
	channelID, err := strconv.Atoi(channelIDStr)
	if err != nil {
		sendError(w, "INVALID_ID", "Invalid channel ID", http.StatusBadRequest)
		return
	}

	var req PermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "INVALID_REQUEST", "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err = db.Exec(
		"INSERT OR REPLACE INTO channel_permissions (user_id, channel_id, permissions) VALUES (?, ?, ?)",
		req.UserID, channelID, req.Permissions,
	)
	if err != nil {
		sendError(w, "PERMISSION_ERROR", "Failed to set permissions", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, "PERMISSIONS_SET", "Permissions set successfully", nil)
}
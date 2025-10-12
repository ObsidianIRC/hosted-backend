package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// RegisterAccountRequest represents account registration request
type RegisterAccountRequest struct {
	AccountName  string `json:"account_name"`
	EmailAddress string `json:"email_address"`
	PasswordB64  string `json:"password_b64"`
}

// LoginRequest represents login request
type LoginRequest struct {
	AccountName string `json:"account_name"`
	PasswordB64 string `json:"password_b64"`
}

// UpdateAccountRequest represents account update request
type UpdateAccountRequest struct {
	EmailAddress *string `json:"email_address,omitempty"`
	PasswordB64  *string `json:"password_b64,omitempty"`
}

// MetadataRequest represents metadata request
type MetadataRequest struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// APIResponse represents API response
type APIResponse struct {
	Success bool        `json:"success"`
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// handleRegisterAccount handles account registration
func handleRegisterAccount(w http.ResponseWriter, r *http.Request) {
	var req RegisterAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "INVALID_REQUEST", "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Decode password
	password, err := base64.StdEncoding.DecodeString(req.PasswordB64)
	if err != nil {
		sendError(w, "INVALID_PASSWORD", "Invalid base64 password", http.StatusBadRequest)
		return
	}

	// Hash password
	hash, err := hashPassword(string(password))
	if err != nil {
		sendError(w, "HASH_ERROR", "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Insert user
	result, err := db.Exec(
		"INSERT INTO users (account_name, email_address, password_hash) VALUES (?, ?, ?)",
		req.AccountName, req.EmailAddress, hash,
	)
	if err != nil {
		sendError(w, "REGISTRATION_FAILED", "Account registration failed: "+err.Error(), http.StatusConflict)
		return
	}

	userID, _ := result.LastInsertId()

	// Create verification code
	code, err := generateVerificationCode()
	if err != nil {
		sendError(w, "VERIFICATION_ERROR", "Failed to generate verification code", http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	_, err = db.Exec(
		"INSERT INTO email_verifications (user_id, code, expires_at) VALUES (?, ?, ?)",
		userID, code, expiresAt,
	)
	if err != nil {
		sendError(w, "VERIFICATION_ERROR", "Failed to create verification", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, "ACCOUNT_CREATED", "Account created successfully", map[string]interface{}{
		"user_id": userID,
		"verification_code": code,
	})
}

// handleLogin handles account login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "INVALID_REQUEST", "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Decode password
	password, err := base64.StdEncoding.DecodeString(req.PasswordB64)
	if err != nil {
		sendError(w, "INVALID_PASSWORD", "Invalid base64 password", http.StatusBadRequest)
		return
	}

	// Get user
	var user User
	var hash string
	err = db.QueryRow(
		"SELECT id, account_name, email_address, date_registered, last_logged_in, password_hash FROM users WHERE account_name = ?",
		req.AccountName,
	).Scan(&user.ID, &user.AccountName, &user.EmailAddress, &user.DateRegistered, &user.LastLoggedIn, &hash)

	if err != nil {
		sendError(w, "LOGIN_FAILED", "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Verify password
	valid, err := verifyPassword(string(password), hash)
	if err != nil || !valid {
		sendError(w, "LOGIN_FAILED", "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Update last logged in
	_, err = db.Exec("UPDATE users SET last_logged_in = CURRENT_TIMESTAMP WHERE id = ?", user.ID)
	if err != nil {
		// Log error but don't fail login
		fmt.Printf("Failed to update last_logged_in: %v\n", err)
	}

	sendSuccess(w, "LOGIN_SUCCESS", "Login successful", user)
}

// handleUpdateAccount handles account updates
func handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		sendError(w, "INVALID_ID", "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req UpdateAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "INVALID_REQUEST", "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Build update query
	setParts := []string{}
	args := []interface{}{}

	if req.EmailAddress != nil {
		setParts = append(setParts, "email_address = ?")
		args = append(args, *req.EmailAddress)
	}

	if req.PasswordB64 != nil {
		password, err := base64.StdEncoding.DecodeString(*req.PasswordB64)
		if err != nil {
			sendError(w, "INVALID_PASSWORD", "Invalid base64 password", http.StatusBadRequest)
			return
		}
		hash, err := hashPassword(string(password))
		if err != nil {
			sendError(w, "HASH_ERROR", "Failed to hash password", http.StatusInternalServerError)
			return
		}
		setParts = append(setParts, "password_hash = ?")
		args = append(args, hash)
	}

	if len(setParts) == 0 {
		sendError(w, "NO_UPDATES", "No fields to update", http.StatusBadRequest)
		return
	}

	query := "UPDATE users SET " + strings.Join(setParts, ", ") + " WHERE id = ?"
	args = append(args, userID)

	result, err := db.Exec(query, args...)
	if err != nil {
		sendError(w, "UPDATE_FAILED", "Failed to update account", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		sendError(w, "USER_NOT_FOUND", "User not found", http.StatusNotFound)
		return
	}

	sendSuccess(w, "ACCOUNT_UPDATED", "Account updated successfully", nil)
}

// handleGetAccount handles getting account info
func handleGetAccount(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		sendError(w, "INVALID_ID", "Invalid user ID", http.StatusBadRequest)
		return
	}

	var user User
	err = db.QueryRow(
		"SELECT id, account_name, email_address, date_registered, last_logged_in FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.AccountName, &user.EmailAddress, &user.DateRegistered, &user.LastLoggedIn)

	if err != nil {
		sendError(w, "USER_NOT_FOUND", "User not found", http.StatusNotFound)
		return
	}

	sendSuccess(w, "ACCOUNT_RETRIEVED", "Account retrieved successfully", user)
}

// handleSetUserMetadata handles setting user metadata
func handleSetUserMetadata(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userIDStr := vars["id"]
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		sendError(w, "INVALID_ID", "Invalid user ID", http.StatusBadRequest)
		return
	}

	var req MetadataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, "INVALID_REQUEST", "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err = db.Exec(
		"INSERT OR REPLACE INTO user_metadata (user_id, key, value) VALUES (?, ?, ?)",
		userID, req.Key, req.Value,
	)
	if err != nil {
		sendError(w, "METADATA_ERROR", "Failed to set metadata", http.StatusInternalServerError)
		return
	}

	sendSuccess(w, "METADATA_SET", "Metadata set successfully", nil)
}

// handleVerifyEmail handles email verification
func handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	code := vars["code"]

	result, err := db.Exec(
		"UPDATE email_verifications SET verified = TRUE WHERE code = ? AND expires_at > CURRENT_TIMESTAMP AND verified = FALSE",
		code,
	)
	if err != nil {
		sendError(w, "VERIFICATION_ERROR", "Failed to verify email", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		sendError(w, "INVALID_CODE", "Invalid or expired verification code", http.StatusBadRequest)
		return
	}

	sendSuccess(w, "EMAIL_VERIFIED", "Email verified successfully", nil)
}

// sendSuccess sends a success response
func sendSuccess(w http.ResponseWriter, code, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(APIResponse{
		Success: true,
		Code:    code,
		Message: message,
		Data:    data,
	})
}

// sendError sends an error response
func sendError(w http.ResponseWriter, code, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Code:    code,
		Message: message,
	})
}
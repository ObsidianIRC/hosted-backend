package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/argon2"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// User represents a user account
type User struct {
	ID             int       `json:"id"`
	AccountName    string    `json:"account_name"`
	EmailAddress   string    `json:"email_address"`
	DateRegistered time.Time `json:"date_registered"`
	LastLoggedIn   *time.Time `json:"last_logged_in"`
	PasswordHash   string    `json:"-"`
}

// Channel represents a channel
type Channel struct {
	ID           int    `json:"id"`
	ChannelName  string `json:"channel_name"`
	ChannelTopic string `json:"channel_topic"`
	Modes        string `json:"modes"`
}

// UserMetadata represents user metadata
type UserMetadata struct {
	ID    int    `json:"id"`
	UserID int   `json:"user_id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ChannelMetadata represents channel metadata
type ChannelMetadata struct {
	ID        int    `json:"id"`
	ChannelID int    `json:"channel_id"`
	Key       string `json:"key"`
	Value     string `json:"value"`
}

// ChannelPermission represents channel permissions
type ChannelPermission struct {
	ID         int    `json:"id"`
	UserID     int    `json:"user_id"`
	ChannelID  int    `json:"channel_id"`
	Permissions string `json:"permissions"`
}

// EmailVerification represents email verification
type EmailVerification struct {
	ID        int       `json:"id"`
	UserID    int       `json:"user_id"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
	Verified  bool      `json:"verified"`
}

// InitDB initializes the SQLite database
func InitDB() error {
	var err error
	db, err = sql.Open("sqlite3", "./irc_backend.db")
	if err != nil {
		return err
	}

	// Create tables
	if err := createTables(); err != nil {
		return err
	}

	// Seed data
	if err := seedData(); err != nil {
		return err
	}

	return nil
}

// createTables creates all necessary tables
func createTables() error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			account_name TEXT UNIQUE NOT NULL,
			email_address TEXT UNIQUE NOT NULL,
			date_registered DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_logged_in DATETIME,
			password_hash TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS user_metadata (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			key TEXT NOT NULL,
			value TEXT,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			UNIQUE(user_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS channels (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			channel_name TEXT UNIQUE NOT NULL,
			channel_topic TEXT,
			modes TEXT DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS channel_metadata (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			channel_id INTEGER NOT NULL,
			key TEXT NOT NULL,
			value TEXT,
			FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE,
			UNIQUE(channel_id, key)
		)`,
		`CREATE TABLE IF NOT EXISTS channel_permissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			channel_id INTEGER NOT NULL,
			permissions TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (channel_id) REFERENCES channels(id) ON DELETE CASCADE,
			UNIQUE(user_id, channel_id)
		)`,
		`CREATE TABLE IF NOT EXISTS email_verifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			code TEXT UNIQUE NOT NULL,
			expires_at DATETIME NOT NULL,
			verified BOOLEAN DEFAULT FALSE,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
	}

	for _, query := range tables {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("failed to create table: %v", err)
		}
	}

	return nil
}

// seedData adds initial data
func seedData() error {
	// Check if admin user exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM users WHERE account_name = ?", "admin").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		// Create admin user
		password := "admin123" // In production, use proper password
		hash, err := hashPassword(password)
		if err != nil {
			return err
		}

		_, err = db.Exec(
			"INSERT INTO users (account_name, email_address, password_hash) VALUES (?, ?, ?)",
			"admin", "admin@example.com", hash,
		)
		if err != nil {
			return err
		}

		log.Println("Seeded admin user: admin/admin123")
	}

	return nil
}

// hashPassword hashes a password using Argon2id
func hashPassword(password string) (string, error) {
	saltSize := 32
	if saltSizeStr := os.Getenv("PASSWORD_SALT_SIZE"); saltSizeStr != "" {
		if parsed, err := strconv.Atoi(saltSizeStr); err == nil && parsed > 0 {
			saltSize = parsed
		}
	}
	
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return base64.StdEncoding.EncodeToString(append(salt, hash...)), nil
}

// verifyPassword verifies a password against a hash
func verifyPassword(password, hash string) (bool, error) {
	data, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		return false, err
	}

	hashSize := 32 // Argon2 output size
	if len(data) < hashSize {
		return false, fmt.Errorf("invalid hash")
	}

	salt := data[:len(data)-hashSize]
	storedHash := data[len(data)-hashSize:]

	computedHash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)

	return string(computedHash) == string(storedHash), nil
}

// generateVerificationCode generates a random verification code
func generateVerificationCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
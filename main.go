package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type UploadRequest struct {
	URL string `json:"url"`
}

type UploadResponse struct {
	SavedURL string `json:"saved_url"`
}

func corsHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// setCORSHeaders sets comprehensive CORS headers for API endpoints
func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
	w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
}

// processImage processes images based on configuration
func processImage(data []byte, author string, jwtExpiry time.Time, serverExpiry time.Time, compressionEnabled bool, maxWidth, maxHeight, jpegQuality int, convertToJpeg bool) ([]byte, string, error) {
	// Decode image
	img, format, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, "", err
	}

	processed := false

	// Apply compression if enabled
	if compressionEnabled {
		// Resize to fit within configured dimensions
		img = imaging.Fit(img, maxWidth, maxHeight, imaging.Lanczos)
		processed = true
	}

	// Encode based on configuration
	buf := new(bytes.Buffer)

	if convertToJpeg || format == "jpeg" || processed {
		// Convert to JPEG
		err = jpeg.Encode(buf, img, &jpeg.Options{Quality: jpegQuality})
		if err != nil {
			return nil, "", err
		}

		encoded := buf.Bytes()

		// Add metadata as JPEG comment (author format: nick:account)
		metadata := map[string]string{
			"author":       author,
			"jwt_expiry":   jwtExpiry.Format(time.RFC3339),
			"server_expiry": serverExpiry.Format(time.RFC3339),
		}
		commentBytes, err := json.Marshal(metadata)
		if err != nil {
			// Fallback to plain text if JSON marshaling fails
			comment := "Author: " + author + "; JWT Expires: " + jwtExpiry.Format(time.RFC3339) + "; Server Expires: " + serverExpiry.Format(time.RFC3339)
			commentBytes = []byte(comment)
		}

		// Insert COM segment after SOI (FF D8)
		if len(encoded) >= 2 {
			comMarker := []byte{0xFF, 0xFE}
			length := uint16(len(commentBytes) + 2) // +2 for length field
			lengthBytes := []byte{byte(length >> 8), byte(length)}
			comSegment := append(comMarker, lengthBytes...)
			comSegment = append(comSegment, commentBytes...)

			// Insert after SOI
			result := make([]byte, 0, len(encoded)+len(comSegment))
			result = append(result, encoded[:2]...)
			result = append(result, comSegment...)
			result = append(result, encoded[2:]...)
			return result, "jpeg", nil
		}

		return encoded, "jpeg", nil
	} else {
		// Keep original format (PNG, GIF, etc.)
		switch format {
		case "png":
			err = imaging.Encode(buf, img, imaging.PNG)
		case "gif":
			err = imaging.Encode(buf, img, imaging.GIF)
		default:
			// Fallback to JPEG
			err = jpeg.Encode(buf, img, &jpeg.Options{Quality: jpegQuality})
		}
		if err != nil {
			return nil, "", err
		}
		return buf.Bytes(), format, nil
	}
}


func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Printf("Warning: Error loading .env file: %v\n", err)
	}

	// Create images directory if it doesn't exist
	os.MkdirAll("images", os.ModePerm)

	// Read port from environment variable, default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Read deletion timeout from environment variable, default to 2 minutes
	deleteTimeoutStr := os.Getenv("DELETE_TIMEOUT_MINUTES")
	deleteTimeoutMinutes := 2
	if deleteTimeoutStr != "" {
		if parsed, err := strconv.Atoi(deleteTimeoutStr); err == nil {
			deleteTimeoutMinutes = parsed
		}
	}
	deleteTimeout := time.Duration(deleteTimeoutMinutes) * time.Minute

	// Read max upload size from environment variable, default to 32MB
	maxUploadSizeStr := os.Getenv("MAX_UPLOAD_SIZE_MB")
	maxUploadSizeMB := 32
	if maxUploadSizeStr != "" {
		if parsed, err := strconv.Atoi(maxUploadSizeStr); err == nil {
			maxUploadSizeMB = parsed
		}
	}
	maxUploadSize := int64(maxUploadSizeMB) << 20

	// Read image processing configuration
	imageCompressionEnabled := os.Getenv("IMAGE_COMPRESSION_ENABLED") == "true"
	imageMaxWidth := 1920
	if widthStr := os.Getenv("IMAGE_MAX_WIDTH"); widthStr != "" {
		if parsed, err := strconv.Atoi(widthStr); err == nil && parsed > 0 {
			imageMaxWidth = parsed
		}
	}
	imageMaxHeight := 1080
	if heightStr := os.Getenv("IMAGE_MAX_HEIGHT"); heightStr != "" {
		if parsed, err := strconv.Atoi(heightStr); err == nil && parsed > 0 {
			imageMaxHeight = parsed
		}
	}
	imageJpegQuality := 85
	if qualityStr := os.Getenv("IMAGE_JPEG_QUALITY"); qualityStr != "" {
		if parsed, err := strconv.Atoi(qualityStr); err == nil && parsed > 0 && parsed <= 100 {
			imageJpegQuality = parsed
		}
	}
	imageConvertToJpeg := os.Getenv("IMAGE_CONVERT_TO_JPEG") == "true"

	// Initialize database
	if err := InitDB(); err != nil {
		fmt.Printf("Failed to initialize database: %v\n", err)
		os.Exit(1)
	}

	// Initialize IRC connection
	if err := InitIRCConn(); err != nil {
		fmt.Printf("Failed to connect to IRC: %v\n", err)
		// Continue without IRC features
	}

	r := mux.NewRouter()

	// File upload (requires JWT)
	r.HandleFunc("/upload", AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uploadHandler(w, r, port, deleteTimeout, maxUploadSize, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
	}, false)).Methods("POST", "OPTIONS")

	// Avatar uploads (require JWT)
	r.HandleFunc("/upload/avatar/user", AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uploadUserAvatarHandler(w, r, maxUploadSize, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
	}, false)).Methods("POST", "OPTIONS")

	r.HandleFunc("/upload/avatar/channel/{channel}", AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uploadChannelAvatarHandler(w, r, maxUploadSize, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
	}, false)).Methods("POST", "OPTIONS")

	// Image serving
	r.PathPrefix("/images/").Handler(corsHandler(http.StripPrefix("/images/", http.FileServer(http.Dir("images")))))

	// IRC info endpoints (require JWT + IRCop)
	r.HandleFunc("/irc/users", AuthMiddleware(handleIRCUsers, true)).Methods("GET")
	r.HandleFunc("/irc/channels", AuthMiddleware(handleIRCChannels, true)).Methods("GET")
	r.HandleFunc("/irc/bans", AuthMiddleware(handleIRCBans, true)).Methods("GET")
	r.HandleFunc("/irc/stats", AuthMiddleware(handleIRCStats, true)).Methods("GET")
	r.HandleFunc("/irc/server-uptime", AuthMiddleware(handleIRCServerUptime, true)).Methods("GET")

	// Account management (require server key)
	accountRouter := r.PathPrefix("/irc/accounts").Subrouter()
	accountRouter.Use(ServerAuthMiddleware)
	accountRouter.HandleFunc("/register", handleRegisterAccount).Methods("POST")
	accountRouter.HandleFunc("/login", handleLogin).Methods("POST")
	accountRouter.HandleFunc("/{id}", handleGetAccount).Methods("GET")
	accountRouter.HandleFunc("/{id}", handleUpdateAccount).Methods("PUT")
	accountRouter.HandleFunc("/{id}/metadata", handleSetUserMetadata).Methods("POST")
	accountRouter.HandleFunc("/verify/{code}", handleVerifyEmail).Methods("GET")

	// Channel management (require server key)
	channelRouter := r.PathPrefix("/irc/channels").Subrouter()
	channelRouter.Use(ServerAuthMiddleware)
	channelRouter.HandleFunc("/register", handleRegisterChannel).Methods("POST")
	channelRouter.HandleFunc("/{id}", handleGetChannel).Methods("GET")
	channelRouter.HandleFunc("/{id}", handleUpdateChannel).Methods("PUT")
	channelRouter.HandleFunc("/{id}/metadata", handleSetChannelMetadata).Methods("POST")
	channelRouter.HandleFunc("/{id}/permissions", handleSetChannelPermissions).Methods("POST")

	fmt.Printf("Server starting on :%s\n", port)
	http.ListenAndServe(":"+port, r)
}

func uploadHandler(w http.ResponseWriter, r *http.Request, port string, deleteTimeout time.Duration, maxUploadSize int64, imageCompressionEnabled bool, imageMaxWidth, imageMaxHeight, imageJpegQuality int, imageConvertToJpeg bool) {
	setCORSHeaders(w)

	fmt.Println("Request method:", r.Method)

	if r.Method == http.MethodOptions {
		fmt.Println("Handling OPTIONS request")
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get JWT claims for author info
	claims := r.Context().Value("jwt_claims").(*JWTClaims)
	// Create combined nick:account format
	nick := claims.Sub
	account := claims.Account
	if account == "" {
		account = "0"
	}
	author := nick + ":" + account
	jwtExpiry := time.Unix(claims.Exp, 0)  // JWT token expiration time
	expiry := time.Now().Add(deleteTimeout)

	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") {
		// Multipart file upload
		err := r.ParseMultipartForm(maxUploadSize) // Configurable max size
		if err != nil {
			http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}

		uploadedFile, _, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer uploadedFile.Close()

		// Read image data
		data, err := io.ReadAll(uploadedFile)
		if err != nil {
			http.Error(w, "Failed to read uploaded file", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, jwtExpiry, expiry, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Generate unique filename based on output format
		timestamp := time.Now().UnixNano()
		filename := strconv.FormatInt(timestamp, 10) + "." + format
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Schedule deletion after specified timeout
		time.AfterFunc(deleteTimeout, func() {
			os.Remove(filePath)
		})

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else if strings.HasPrefix(contentType, "image/") {
		// Raw image upload
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(body, author, jwtExpiry, expiry, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Generate unique filename based on output format
		timestamp := time.Now().UnixNano()
		filename := strconv.FormatInt(timestamp, 10) + "." + format
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Schedule deletion after specified timeout
		time.AfterFunc(deleteTimeout, func() {
			os.Remove(filePath)
		})

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else if strings.Contains(contentType, "application/json") {
		// JSON URL upload
		var req UploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// URL upload
		resp, err := http.Get(req.URL)
		if err != nil {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}

		// Read image data
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read downloaded image", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, jwtExpiry, expiry, imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Generate unique filename based on output format
		timestamp := time.Now().UnixNano()
		filename := strconv.FormatInt(timestamp, 10) + "." + format
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Schedule deletion after specified timeout
		time.AfterFunc(deleteTimeout, func() {
			os.Remove(filePath)
		})

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Unsupported content type: "+contentType, http.StatusBadRequest)
		return
	}
}

func uploadUserAvatarHandler(w http.ResponseWriter, r *http.Request, maxUploadSize int64, imageCompressionEnabled bool, imageMaxWidth, imageMaxHeight, imageJpegQuality int, imageConvertToJpeg bool) {
	fmt.Println("uploadUserAvatarHandler called")
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get JWT claims
	claims := r.Context().Value("jwt_claims").(*JWTClaims)

	// Create author string (nick:account format)
	nick := claims.Sub
	account := claims.Account
	if account == "" {
		account = "0"
	}
	author := nick + ":" + account

	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") {
		// Multipart file upload
		err := r.ParseMultipartForm(maxUploadSize)
		if err != nil {
			http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}

		uploadedFile, _, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer uploadedFile.Close()

		// Read image data
		data, err := io.ReadAll(uploadedFile)
		if err != nil {
			http.Error(w, "Failed to read uploaded file", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this account
		removeOldUserAvatar(account)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_user_%s_%d.%s", account, timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	} else if strings.HasPrefix(contentType, "image/") {
		// Raw image upload
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(body, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this account
		removeOldUserAvatar(claims.Account)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_user_%s_%d.%s", claims.Account, timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	} else if contentType == "application/json" {
		// JSON URL upload
		var req UploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Download image from URL
		resp, err := http.Get(req.URL)
		if err != nil {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}

		// Read image data
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read downloaded image", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this account
		removeOldUserAvatar(claims.Account)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_user_%s_%d.%s", claims.Account, timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Unsupported content type: "+contentType, http.StatusBadRequest)
		return
	}
}

func uploadChannelAvatarHandler(w http.ResponseWriter, r *http.Request, maxUploadSize int64, imageCompressionEnabled bool, imageMaxWidth, imageMaxHeight, imageJpegQuality int, imageConvertToJpeg bool) {
	fmt.Println("uploadChannelAvatarHandler called")
	setCORSHeaders(w)

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get JWT claims
	claims := r.Context().Value("jwt_claims").(*JWTClaims)

	// Check if account exists
	if claims.Account == "" {
		http.Error(w, fmt.Sprintf("Account required for avatar upload. JWT claims: sub=%s, account='%s', umodes=%v, cmodes=%v", claims.Sub, claims.Account, claims.Umodes, claims.Cmodes), http.StatusForbidden)
		return
	}

	// Check channel permissions - must have 'o', 'a', or 'q' in cmodes
	hasPermission := false
	for _, mode := range claims.Cmodes {
		if mode == "o" || mode == "a" || mode == "q" {
			hasPermission = true
			break
		}
	}
	if !hasPermission {
		http.Error(w, "Channel operator/admin/owner permission required", http.StatusForbidden)
		return
	}

	// Get channel from URL
	vars := mux.Vars(r)
	channel := vars["channel"]
	if channel == "" {
		http.Error(w, "Channel name required", http.StatusBadRequest)
		return
	}

	// Create author string (nick:account format)
	nick := claims.Sub
	account := claims.Account
	if account == "" {
		account = "0"
	}
	author := nick + ":" + account

	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") {
		// Multipart file upload
		err := r.ParseMultipartForm(maxUploadSize)
		if err != nil {
			http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}

		uploadedFile, _, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer uploadedFile.Close()

		// Read image data
		data, err := io.ReadAll(uploadedFile)
		if err != nil {
			http.Error(w, "Failed to read uploaded file", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this channel
		removeOldChannelAvatar(channel)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_channel_%s_%d.%s", strings.ReplaceAll(channel, "#", "_hash_"), timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	} else if strings.HasPrefix(contentType, "image/") {
		// Raw image upload
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(body, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this channel
		removeOldChannelAvatar(channel)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_channel_%s_%d.%s", strings.ReplaceAll(channel, "#", "_hash_"), timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	} else if contentType == "application/json" {
		// JSON URL upload
		var req UploadRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Download image from URL
		resp, err := http.Get(req.URL)
		if err != nil {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			http.Error(w, "Failed to download image", http.StatusInternalServerError)
			return
		}

		// Read image data
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, "Failed to read downloaded image", http.StatusInternalServerError)
			return
		}

		// Process image (resize, strip EXIF, add custom EXIF)
		processedData, format, err := processImage(data, author, time.Now().Add(365*24*time.Hour), time.Now().Add(365*24*time.Hour), imageCompressionEnabled, imageMaxWidth, imageMaxHeight, imageJpegQuality, imageConvertToJpeg)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Remove old avatar for this channel
		removeOldChannelAvatar(channel)

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := fmt.Sprintf("avatar_channel_%s_%d.%s", strings.ReplaceAll(channel, "#", "_hash_"), timestamp, format)
		filePath := filepath.Join("images", filename)

		// Save the processed image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(processedData)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}

		// Return the saved URL
		savedURL := fmt.Sprintf("/images/%s", filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Unsupported content type: "+contentType, http.StatusBadRequest)
		return
	}
}

func removeOldUserAvatar(account string) {
	files, err := os.ReadDir("images")
	if err != nil {
		return
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), "avatar_user_"+account+"_") {
			os.Remove(filepath.Join("images", file.Name()))
		}
	}
}

func removeOldChannelAvatar(channel string) {
	files, err := os.ReadDir("images")
	if err != nil {
		return
	}

	safeChannel := strings.ReplaceAll(channel, "#", "_hash_")
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "avatar_channel_"+safeChannel+"_") {
			os.Remove(filepath.Join("images", file.Name()))
		}
	}
}

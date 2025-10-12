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
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// processImage resizes image to 1080p, strips EXIF, and adds custom EXIF data
func processImage(data []byte, author string, expiry time.Time) ([]byte, error) {
	// Decode image
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	// Resize to fit within 1920x1080 (1080p)
	img = imaging.Fit(img, 1920, 1080, imaging.Lanczos)

	// Encode to JPEG (strips existing EXIF)
	buf := new(bytes.Buffer)
	err = jpeg.Encode(buf, img, &jpeg.Options{Quality: 85})
	if err != nil {
		return nil, err
	}

	encoded := buf.Bytes()

	// Add custom EXIF data
	exifData := createEXIF(author, expiry)

	// Insert APP1 segment after SOI (FF D8)
	if len(encoded) >= 2 {
		app1Marker := []byte{0xFF, 0xE1}
		length := uint16(len(exifData) + 2) // +2 for length field
		lengthBytes := []byte{byte(length >> 8), byte(length)}
		app1Segment := append(app1Marker, lengthBytes...)
		app1Segment = append(app1Segment, exifData...)

		// Insert after SOI
		result := make([]byte, 0, len(encoded)+len(app1Segment))
		result = append(result, encoded[:2]...)
		result = append(result, app1Segment...)
		result = append(result, encoded[2:]...)
		return result, nil
	}

	return encoded, nil
}

// createEXIF creates basic EXIF data with author and expiry information
func createEXIF(author string, expiry time.Time) []byte {
	desc := "Author: " + author + "; Expires: " + expiry.Format(time.RFC3339)
	exif := []byte("Exif\x00\x00II*\x00\x08\x00\x00\x00\x01\x00\x0E\x01\x02\x00")
	descBytes := []byte(desc + "\x00")
	lenBytes := make([]byte, 4)
	lenBytes[0] = byte(len(descBytes))
	lenBytes[1] = byte(len(descBytes) >> 8)
	offset := []byte{0x16, 0x00, 0x00, 0x00}
	nextIfd := []byte{0x00, 0x00, 0x00, 0x00}
	exif = append(exif, lenBytes...)
	exif = append(exif, offset...)
	exif = append(exif, nextIfd...)
	exif = append(exif, descBytes...)
	return exif
}

func main() {
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
		uploadHandler(w, r, port, deleteTimeout, maxUploadSize)
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

func uploadHandler(w http.ResponseWriter, r *http.Request, port string, deleteTimeout time.Duration, maxUploadSize int64) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	fmt.Println("Request method:", r.Method)

	if r.Method == http.MethodOptions {
		fmt.Println("Handling OPTIONS request")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get JWT claims for author info
	claims := r.Context().Value("jwt_claims").(*JWTClaims)
	author := claims.Account
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
		processedData, err := processImage(data, author, expiry)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Generate unique filename (always .jpg since we convert to JPEG)
		timestamp := time.Now().UnixNano()
		filename := strconv.FormatInt(timestamp, 10) + ".jpg"
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
		savedURL := fmt.Sprintf("http://localhost:%s/images/%s", port, filename)
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
		processedData, err := processImage(body, author, expiry)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Generate unique filename (always .jpg since we convert to JPEG)
		timestamp := time.Now().UnixNano()
		filename := strconv.FormatInt(timestamp, 10) + ".jpg"
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
		savedURL := fmt.Sprintf("http://localhost:%s/images/%s", port, filename)
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
		processedData, err := processImage(data, author, expiry)
		if err != nil {
			http.Error(w, "Failed to process image", http.StatusInternalServerError)
			return
		}

		// Generate unique filename (always .jpg since we convert to JPEG)
		timestamp := time.Now().UnixNano()
		filename := strconv.FormatInt(timestamp, 10) + ".jpg"
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
		savedURL := fmt.Sprintf("http://localhost:%s/images/%s", port, filename)
		response := UploadResponse{SavedURL: savedURL}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		http.Error(w, "Unsupported content type: "+contentType, http.StatusBadRequest)
		return
	}
}
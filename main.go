package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h.ServeHTTP(w, r)
	})
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

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		uploadHandler(w, r, port, deleteTimeout, maxUploadSize)
	})
	http.Handle("/images/", corsHandler(http.StripPrefix("/images/", http.FileServer(http.Dir("images")))))

	fmt.Printf("Server starting on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}

func uploadHandler(w http.ResponseWriter, r *http.Request, port string, deleteTimeout time.Duration, maxUploadSize int64) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	fmt.Println("Request method:", r.Method)

	if r.Method == http.MethodOptions {
		fmt.Println("Handling OPTIONS request")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "multipart/form-data") {
		// Multipart file upload
		err := r.ParseMultipartForm(maxUploadSize) // Configurable max size
		if err != nil {
			http.Error(w, "Failed to parse multipart form: "+err.Error(), http.StatusBadRequest)
			return
		}

		uploadedFile, header, err := r.FormFile("image")
		if err != nil {
			http.Error(w, "Failed to get uploaded file: "+err.Error(), http.StatusBadRequest)
			return
		}
		defer uploadedFile.Close()

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		ext := filepath.Ext(header.Filename)
		if ext == "" {
			ext = ".jpg"
		}
		filename := strconv.FormatInt(timestamp, 10) + ext
		filePath := filepath.Join("images", filename)

		// Save the image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = io.Copy(file, uploadedFile)
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

		ext := "." + strings.TrimPrefix(contentType, "image/")
		if ext == ".jpeg" {
			ext = ".jpg"
		}
		timestamp := time.Now().UnixNano()
		filename := strconv.FormatInt(timestamp, 10) + ext
		filePath := filepath.Join("images", filename)

		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.Write(body)
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

		// Generate unique filename
		timestamp := time.Now().UnixNano()
		filename := strconv.FormatInt(timestamp, 10) + ".jpg" // Assume jpg, but could check content-type
		filePath := filepath.Join("images", filename)

		// Save the image
		file, err := os.Create(filePath)
		if err != nil {
			http.Error(w, "Failed to save image", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = io.Copy(file, resp.Body)
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
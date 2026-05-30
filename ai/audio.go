package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"time"
)

type OpenAIAudio struct {
	BaseURL string
	Model   string
	Voice   string
	APIKey  string
	Client  *http.Client
}

func TTSFromEnv() *OpenAIAudio {
	key := os.Getenv("AI_TTS_API_KEY")
	if key == "" {
		key = os.Getenv("AI_API_KEY")
	}
	base := os.Getenv("AI_TTS_BASE_URL")
	if base == "" {
		base = "https://gen.pollinations.ai/v1"
	}
	model := os.Getenv("AI_TTS_MODEL")
	if model == "" {
		model = "openai-audio"
	}
	voice := os.Getenv("AI_TTS_VOICE")
	if voice == "" {
		voice = "alloy"
	}
	return &OpenAIAudio{
		BaseURL: strings.TrimRight(base, "/"),
		Model:   model,
		Voice:   voice,
		APIKey:  key,
		Client:  &http.Client{Timeout: 60 * time.Second},
	}
}

type ttsRequest struct {
	Model string `json:"model"`
	Input string `json:"input"`
	Voice string `json:"voice"`
}

func (p *OpenAIAudio) TTS(ctx context.Context, req TTSRequest) ([]byte, string, error) {
	voice := req.Voice
	if voice == "" {
		voice = p.Voice
	}
	body, err := json.Marshal(ttsRequest{
		Model: p.Model,
		Input: req.Text,
		Voice: voice,
	})
	if err != nil {
		return nil, "", err
	}
	endpoint := p.BaseURL + "/audio/speech"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", "obbyircd-orca/0.1")
	if p.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	resp, err := p.Client.Do(httpReq)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode/100 != 2 {
		return nil, "", fmt.Errorf("tts: %s: %s", resp.Status, truncate(string(data), 240))
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "audio/mpeg"
	}
	return data, ct, nil
}

type OpenAITranscribe struct {
	BaseURL string
	Model   string
	APIKey  string
	Client  *http.Client
}

func STTFromEnv() *OpenAITranscribe {
	key := os.Getenv("AI_STT_API_KEY")
	if key == "" {
		key = os.Getenv("AI_API_KEY")
	}
	base := os.Getenv("AI_STT_BASE_URL")
	if base == "" {
		base = "https://gen.pollinations.ai/v1"
	}
	model := os.Getenv("AI_STT_MODEL")
	if model == "" {
		model = "whisper"
	}
	return &OpenAITranscribe{
		BaseURL: strings.TrimRight(base, "/"),
		Model:   model,
		APIKey:  key,
		Client:  &http.Client{Timeout: 60 * time.Second},
	}
}

type sttResponse struct {
	Text string `json:"text"`
}

func (p *OpenAITranscribe) STT(ctx context.Context, req STTRequest) (*STTResponse, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("model", p.Model)
	if req.Language != "" {
		_ = mw.WriteField("language", req.Language)
	}
	mime := req.MimeType
	if mime == "" {
		mime = "audio/wav"
	}
	// Pollinations/OVH STT sniffs the multipart filename's extension and
	// 400s anything unrecognised (notably "audio.bin"). Map the mime to
	// a known-good extension.
	ext := "wav"
	switch mime {
	case "audio/mpeg", "audio/mp3":
		ext = "mp3"
	case "audio/webm":
		ext = "webm"
	case "audio/ogg", "audio/opus":
		ext = "ogg"
	case "audio/m4a", "audio/mp4", "audio/x-m4a":
		ext = "m4a"
	case "audio/flac":
		ext = "flac"
	}
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", fmt.Sprintf(
		`form-data; name="file"; filename="audio.%s"`, ext))
	header.Set("Content-Type", mime)
	fw, err := mw.CreatePart(header)
	if err != nil {
		return nil, err
	}
	if _, err := fw.Write(req.Audio); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	endpoint := p.BaseURL + "/audio/transcriptions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", mw.FormDataContentType())
	httpReq.Header.Set("User-Agent", "obbyircd-orca/0.1")
	if p.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}

	resp, err := p.Client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("stt: %s: %s", resp.Status, truncate(string(raw), 240))
	}
	var parsed sttResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	return &STTResponse{Text: parsed.Text}, nil
}

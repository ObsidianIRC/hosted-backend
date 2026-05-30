package ai

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PollinationsAudio is a TTSProvider for Pollinations' GET-style audio
// endpoint at `<base>/audio/{text}?model=...&voice=...`. Distinct from the
// OpenAI-compatible POST `/v1/audio/speech` shape because Pollinations
// doesn't expose any compatible TTS model on /v1/audio/speech — their
// text-to-audio models (qwen-tts, acestep) live on /audio/{text} only.
type PollinationsAudio struct {
	BaseURL string
	Model   string
	Voice   string
	APIKey  string
	Client  *http.Client
}

func NewPollinationsAudio(base, model, voice, key string) *PollinationsAudio {
	if base == "" {
		base = "https://gen.pollinations.ai"
	}
	if model == "" {
		model = "qwen-tts"
	}
	if voice == "" {
		voice = "alloy"
	}
	return &PollinationsAudio{
		BaseURL: strings.TrimRight(base, "/"),
		Model:   model,
		Voice:   voice,
		APIKey:  key,
		Client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (p *PollinationsAudio) TTS(ctx context.Context, req TTSRequest) ([]byte, string, error) {
	voice := req.Voice
	if voice == "" {
		voice = p.Voice
	}
	endpoint := fmt.Sprintf("%s/audio/%s?model=%s&voice=%s",
		p.BaseURL,
		url.PathEscape(req.Text),
		url.QueryEscape(p.Model),
		url.QueryEscape(voice),
	)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", err
	}
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
		ct = "audio/wav"
	}
	return data, ct, nil
}

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type OpenAICompat struct {
	BaseURL string
	Model   string
	APIKey  string
	Client  *http.Client
}

func NewOpenAICompat(baseURL, model, apiKey string) *OpenAICompat {
	if baseURL == "" {
		baseURL = "https://text.pollinations.ai/openai"
	}
	if model == "" {
		model = "openai-large"
	}
	return &OpenAICompat{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Model:   model,
		APIKey:  apiKey,
		Client:  &http.Client{Timeout: 120 * time.Second},
	}
}

func ChatFromEnv() *OpenAICompat {
	key := os.Getenv("AI_CHAT_API_KEY")
	if key == "" {
		key = os.Getenv("AI_API_KEY")
	}
	return NewOpenAICompat(
		os.Getenv("AI_CHAT_BASE_URL"),
		os.Getenv("AI_CHAT_MODEL"),
		key,
	)
}

type openAIChatRequest struct {
	Model      string     `json:"model"`
	Messages   []Message  `json:"messages"`
	Tools      []ToolSpec `json:"tools,omitempty"`
	ToolChoice string     `json:"tool_choice,omitempty"`
	Stream     bool       `json:"stream,omitempty"`
}

type openAIChoice struct {
	Index   int     `json:"index"`
	Message Message `json:"message"`
}

type openAIChatResponse struct {
	Choices []openAIChoice `json:"choices"`
	Usage   Usage          `json:"usage"`
}

func (p *OpenAICompat) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	model := req.Model
	if model == "" {
		model = p.Model
	}

	body, err := json.Marshal(openAIChatRequest{
		Model:      model,
		Messages:   req.Messages,
		Tools:      req.Tools,
		ToolChoice: req.ToolChoice,
		Stream:     false,
	})
	if err != nil {
		return nil, err
	}

	endpoint := p.BaseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
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
		return nil, fmt.Errorf("chat: %s: %s", resp.Status, truncate(string(raw), 240))
	}

	var parsed openAIChatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("chat: parse: %w: %s", err, truncate(string(raw), 240))
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("chat: empty choices: %s", truncate(string(raw), 240))
	}

	return &ChatResponse{
		Message: parsed.Choices[0].Message,
		Usage:   parsed.Usage,
		Raw:     raw,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

package ai

import (
	"context"
	"encoding/json"
)

type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

type Message struct {
	Role       Role            `json:"role"`
	Content    string          `json:"content,omitempty"`
	Name       string          `json:"name,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall      `json:"tool_calls,omitempty"`
	Raw        json.RawMessage `json:"-"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ToolSpec struct {
	Type     string       `json:"type"`
	Function FunctionSpec `json:"function"`
}

type FunctionSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type ChatRequest struct {
	Model      string         `json:"model"`
	Messages   []Message      `json:"messages"`
	Tools      []ToolSpec     `json:"tools,omitempty"`
	ToolChoice string         `json:"tool_choice,omitempty"`
	Stream     bool           `json:"stream,omitempty"`
	Extra      map[string]any `json:"-"`
}

type ChatResponse struct {
	Message Message
	Usage   Usage
	Raw     json.RawMessage
}

type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type ChatProvider interface {
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
}

type TTSRequest struct {
	Voice  string
	Format string
	Text   string
}

type TTSProvider interface {
	TTS(ctx context.Context, req TTSRequest) ([]byte, string, error)
}

type STTRequest struct {
	Audio     []byte
	MimeType  string
	Language  string
}

type STTResponse struct {
	Text string
}

type STTProvider interface {
	STT(ctx context.Context, req STTRequest) (*STTResponse, error)
}

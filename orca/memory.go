package orca

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"backend/ai"
)

// ConvKey identifies a conversation thread.  PMs are keyed per-caller;
// channel threads are keyed by channel name and shared across speakers
// (the model is told who is currently speaking and when it changes).
type ConvKey struct {
	Channel string // channel name or ""
	PMNick  string // peer nick if PM, else ""
}

func (k ConvKey) String() string {
	if k.PMNick != "" {
		return "pm:" + k.PMNick
	}
	return k.Channel
}

type ConvTurn struct {
	Role      ai.Role
	Nick      string
	Account   string
	Msgid     string
	Time      time.Time
	Content   string
	ToolCalls []ai.ToolCall
	ToolCall  ai.ToolCall // for Role=Tool, the call this result satisfies
	ToolName  string
}

type Conversation struct {
	Key         ConvKey
	Turns       []ConvTurn
	LastSpeaker string
	Summary     string // older-turns LLM summary, refreshed on compaction
	mu          sync.Mutex
}

func (c *Conversation) append(t ConvTurn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Turns = append(c.Turns, t)
	if t.Role == ai.RoleUser {
		c.LastSpeaker = t.Nick
	}
}

type Memory struct {
	mu    sync.Mutex
	convs map[string]*Conversation

	maxTurns           int
	compactionTrigger  int
	chat               ai.ChatProvider
}

func NewMemory(chat ai.ChatProvider) *Memory {
	return &Memory{
		convs:             map[string]*Conversation{},
		maxTurns:          24,
		compactionTrigger: 40,
		chat:              chat,
	}
}

func (m *Memory) GetOrCreate(key ConvKey) *Conversation {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := key.String()
	c, ok := m.convs[s]
	if !ok {
		c = &Conversation{Key: key}
		m.convs[s] = c
	}
	return c
}

func (m *Memory) Reset(key ConvKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.convs, key.String())
}

// BuildMessages composes the prompt for one /ask turn. Includes a system
// prompt (multi-speaker / channel context), an optional older-turns
// summary, the recent window of turns, and the new user query.
//
// speakerChanged is true when the current speaker is different from the
// previous speaker on the same conversation; an extra system note marks
// the change so the model treats it as a new participant rather than the
// last one continuing.
func (m *Memory) BuildMessages(conv *Conversation, sysPrompt, speakerNote, userQuery string) []ai.Message {
	conv.mu.Lock()
	turns := append([]ConvTurn{}, conv.Turns...)
	summary := conv.Summary
	conv.mu.Unlock()

	out := []ai.Message{{Role: ai.RoleSystem, Content: sysPrompt}}
	if summary != "" {
		out = append(out, ai.Message{
			Role:    ai.RoleSystem,
			Content: "Earlier in this conversation (summary):\n" + summary,
		})
	}

	start := 0
	if len(turns) > m.maxTurns {
		start = len(turns) - m.maxTurns
	}
	// Walk forward to a safe boundary: never start the window on a
	// `tool` turn (orphaned -- LLM rejects "tool" with no preceding
	// "assistant with tool_calls") and never start on an
	// `assistant{tool_calls}` whose tool responses we'd have to also
	// include. Easiest correct rule: advance to the next `user` turn,
	// which is always a valid boundary in our schema.
	for start < len(turns) {
		t := turns[start]
		if t.Role == ai.RoleUser {
			break
		}
		start++
	}
	for _, t := range turns[start:] {
		switch t.Role {
		case ai.RoleUser:
			label := "[" + t.Nick + "]"
			if t.Account != "" && t.Account != "*" {
				label = "[" + t.Nick + " @ " + t.Account + "]"
			}
			out = append(out, ai.Message{
				Role:    ai.RoleUser,
				Content: label + " " + t.Content,
			})
		case ai.RoleAssistant:
			out = append(out, ai.Message{
				Role:      ai.RoleAssistant,
				Content:   t.Content,
				ToolCalls: t.ToolCalls,
			})
		case ai.RoleTool:
			out = append(out, ai.Message{
				Role:       ai.RoleTool,
				Content:    t.Content,
				ToolCallID: t.ToolCall.ID,
				Name:       t.ToolName,
			})
		}
	}

	if speakerNote != "" {
		out = append(out, ai.Message{Role: ai.RoleSystem, Content: speakerNote})
	}
	if userQuery != "" {
		out = append(out, ai.Message{Role: ai.RoleUser, Content: userQuery})
	}
	return out
}

// MaybeCompact runs an LLM-summary pass when the turn count exceeds the
// compaction trigger. The full transcript still lives in the persistent
// log; only the in-memory prompt context is compacted.
func (m *Memory) MaybeCompact(ctx context.Context, conv *Conversation) {
	conv.mu.Lock()
	turns := len(conv.Turns)
	already := conv.Summary
	conv.mu.Unlock()
	if turns < m.compactionTrigger {
		return
	}
	keep := m.maxTurns
	if keep < 4 {
		keep = 4
	}
	conv.mu.Lock()
	cutoff := len(conv.Turns) - keep
	if cutoff <= 0 {
		conv.mu.Unlock()
		return
	}
	older := conv.Turns[:cutoff]
	conv.mu.Unlock()

	if m.chat == nil {
		return
	}
	var b strings.Builder
	if already != "" {
		fmt.Fprintf(&b, "Previous summary:\n%s\n\nNew turns to fold in:\n", already)
	} else {
		fmt.Fprintf(&b, "Turns to summarize:\n")
	}
	for _, t := range older {
		switch t.Role {
		case ai.RoleUser:
			fmt.Fprintf(&b, "USER %s: %s\n", t.Nick, t.Content)
		case ai.RoleAssistant:
			if t.Content != "" {
				fmt.Fprintf(&b, "ASSISTANT: %s\n", t.Content)
			}
			for _, tc := range t.ToolCalls {
				fmt.Fprintf(&b, "  CALL %s(%s)\n", tc.Function.Name, truncate(tc.Function.Arguments, 80))
			}
		case ai.RoleTool:
			fmt.Fprintf(&b, "  RESULT(%s): %s\n", t.ToolName, truncate(t.Content, 120))
		}
	}

	resp, err := m.chat.Chat(ctx, ai.ChatRequest{
		Messages: []ai.Message{
			{Role: ai.RoleSystem, Content: "You are summarizing a multi-party IRC operator conversation with an admin assistant. Preserve participant names, decisions, tool calls and their findings, and any state that later messages depend on. Be terse."},
			{Role: ai.RoleUser, Content: b.String()},
		},
	})
	if err != nil || resp == nil {
		return
	}

	conv.mu.Lock()
	conv.Summary = strings.TrimSpace(resp.Message.Content)
	conv.Turns = conv.Turns[cutoff:]
	conv.mu.Unlock()
}

package bot

import (
	"context"
	"encoding/json"
)

type Invocation struct {
	CommandInvoke

	OptionsMap map[string]any
	gw         *Gateway
}

func (i *Invocation) String(name string) string {
	if v, ok := i.OptionsMap[name].(string); ok {
		return v
	}
	return ""
}

func (i *Invocation) Int(name string) int64 {
	switch v := i.OptionsMap[name].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

func (i *Invocation) Bool(name string) bool {
	if v, ok := i.OptionsMap[name].(bool); ok {
		return v
	}
	return false
}

func (i *Invocation) Reply(content string) error {
	return i.gw.sendInteractionResponse(i.ID, content, "", false)
}

func (i *Invocation) ReplyPublic(content string) error {
	return i.gw.sendInteractionResponse(i.ID, content, "public", false)
}

func (i *Invocation) Whisper(content string) error {
	return i.gw.sendInteractionResponse(i.ID, content, "private", false)
}

func (i *Invocation) Defer() error {
	return i.gw.send(Frame{Op: OpInteractionDefer, D: mustJSON(map[string]string{"id": i.ID})})
}

func (i *Invocation) NewWorkflow(name string) *WorkflowEmitter {
	target := i.Channel
	if target == "" {
		target = i.Author.Nick
	}
	return newWorkflowEmitter(i.gw, target, i.Msgid, name)
}

type Bot interface {
	Nick() string
	Token() string
	Channels() []string
	Commands() []Command
	Prefix() string
	OnInvoke(ctx context.Context, inv *Invocation) error
	OnEvent(ctx context.Context, eventName string, data json.RawMessage)
}

// GatewayAware is an optional Bot extension: implementers receive the
// live *Gateway on connect (nil on disconnect) so they can send
// spontaneous messages outside of an invocation context, e.g. Orca's
// voice subsystem mirroring transcripts as PRIVMSG into a channel.
type GatewayAware interface {
	SetGateway(g *Gateway)
}

type Registry struct {
	bots []Bot
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(b Bot) {
	r.bots = append(r.bots, b)
}

func (r *Registry) StartAll(ctx context.Context, gatewayURL string) error {
	for _, b := range r.bots {
		go runBot(ctx, b, gatewayURL)
	}
	return nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

package orca

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"

	"backend/ai"
	"backend/bot"
)

type Orca struct {
	nick     string
	token    string
	channels []string

	irc  IRC
	chat ai.ChatProvider
	tts  ai.TTSProvider
	stt  ai.STTProvider

	cmdMu    sync.RWMutex
	commands []bot.Command
	handlers map[string]Handler
}

type Handler func(ctx context.Context, inv *bot.Invocation) error

func New(irc IRC) *Orca {
	nick := envOr("ORCA_NICK", "Orca")
	token := os.Getenv("ORCA_PUSHBOT_TOKEN")
	channels := splitCSV(envOr("ORCA_CHANNELS", "#opers"))

	o := &Orca{
		nick:     nick,
		token:    token,
		channels: channels,
		irc:      irc,
		chat:     ai.ChatFromEnv(),
		tts:      ai.TTSFromEnv(),
		stt:      ai.STTFromEnv(),
		handlers: map[string]Handler{},
	}
	o.registerCommands()
	return o
}

func (o *Orca) Nick() string         { return o.nick }
func (o *Orca) Token() string        { return o.token }
func (o *Orca) Channels() []string   { return o.channels }
func (o *Orca) Prefix() string       { return "!" }

func (o *Orca) Commands() []bot.Command {
	o.cmdMu.RLock()
	defer o.cmdMu.RUnlock()
	out := make([]bot.Command, len(o.commands))
	copy(out, o.commands)
	return out
}

func (o *Orca) registerCommand(c bot.Command, h Handler) {
	o.cmdMu.Lock()
	o.commands = append(o.commands, c)
	o.handlers[strings.ToLower(c.Name)] = h
	o.cmdMu.Unlock()
}

func (o *Orca) registerCommands() {
	o.registerCommand(auditCommand, o.cmdAudit)
	o.registerCommand(scanCommand, o.cmdScan)
	o.registerCommand(explainCommand, o.cmdExplain)
	o.registerCommand(synthBanCommand, o.cmdSynthBan)
}

func (o *Orca) OnInvoke(ctx context.Context, inv *bot.Invocation) error {
	if !inv.Author.IsOper {
		return inv.Whisper("Orca is IRCop-only.")
	}
	o.cmdMu.RLock()
	h, ok := o.handlers[strings.ToLower(inv.Command)]
	o.cmdMu.RUnlock()
	if !ok {
		return inv.Whisper("unknown command: " + inv.Command)
	}
	return h(ctx, inv)
}

func (o *Orca) OnEvent(ctx context.Context, eventName string, data json.RawMessage) {
	switch eventName {
	case "WORKFLOW_ACTION":
		var wa bot.WorkflowAction
		_ = json.Unmarshal(data, &wa)
		log.Printf("[orca] workflow action %s on %s from %s", wa.Action, wa.Target, wa.From.Nick)
	}
}

// Start registers Orca with the registry and starts gateway connections.
// Call once at backend startup.
func Start(ctx context.Context, irc IRC) (*bot.Registry, error) {
	reg := bot.NewRegistry()
	o := New(irc)
	if o.token == "" {
		log.Printf("[orca] ORCA_PUSHBOT_TOKEN unset; Orca disabled")
		return reg, nil
	}
	reg.Register(o)
	gatewayURL := envOr("PUSHBOT_GATEWAY_URL", "ws://127.0.0.1:8600/pushbot/v1/gateway")
	if err := reg.StartAll(ctx, gatewayURL); err != nil {
		return nil, err
	}
	log.Printf("[orca] started as %s, channels=%v, commands=[%s]",
		o.nick, o.channels, bot.CommandNames(o.commands))
	return reg, nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

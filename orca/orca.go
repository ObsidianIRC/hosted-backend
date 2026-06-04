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

	memory *Memory
	logger *Logger

	voiceChannels []string
	voiceTap      VoiceTap
	voice         *voiceSubsystem

	cmdMu     sync.RWMutex
	commands  []bot.Command
	handlers  map[string]Handler
	aiToolMap map[string]Tool

	// gw is the live pushbot Gateway when connected, nil otherwise.
	// Set via SetGateway (bot.GatewayAware) at connect/disconnect.
	// Used by the voice subsystem to mirror transcripts as PRIVMSGs
	// into a channel outside any active invocation.
	gwMu sync.RWMutex
	gw   *bot.Gateway

	// Lazily-built matcher for "is this channel message addressed to
	// me?" -- cached because the nick can't change in one session.
	addrMu      sync.Mutex
	addrMatcher *addressMatcher
}

// SetGateway implements bot.GatewayAware; called by the gateway when
// it (re)connects and again with nil when it tears down.
func (o *Orca) SetGateway(g *bot.Gateway) {
	o.gwMu.Lock()
	o.gw = g
	o.gwMu.Unlock()
}

// Gateway returns the current live gateway, or nil if disconnected.
func (o *Orca) Gateway() *bot.Gateway {
	o.gwMu.RLock()
	defer o.gwMu.RUnlock()
	return o.gw
}

type Handler func(ctx context.Context, inv *bot.Invocation) error

func New(irc IRC) *Orca {
	nick := envOr("ORCA_NICK", "Orca")
	token := os.Getenv("ORCA_PUSHBOT_TOKEN")
	channels := splitCSV(envOr("ORCA_CHANNELS", "#opers"))

	chat := ai.ChatFromEnv()
	o := &Orca{
		nick:      nick,
		token:     token,
		channels:  channels,
		irc:       irc,
		chat:      chat,
		tts:       ai.TTSFromEnv(),
		stt:       ai.STTFromEnv(),
		memory:    NewMemory(chat),
		logger:    OpenLogger(os.Getenv("ORCA_LOG_DB")),
		handlers:  map[string]Handler{},
		aiToolMap: map[string]Tool{},
	}
	o.registerDefaultTools()
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
	o.registerCommand(askCommand, o.cmdAsk)
	o.registerCommand(sentryStatusCommand, o.cmdSentryStatus)
	o.registerCommand(sentryExplainCommand, o.cmdSentryExplain)
	o.registerCommand(sentryLabelCommand, o.cmdSentryLabel)
	o.registerCommand(sentryRecentCommand, o.cmdSentryRecent)
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
		contentStr := ""
		if len(wa.Content) > 0 {
			contentStr = string(wa.Content)
		}
		o.logger.AppendAction(wa.WID, wa.Action, wa.Target, wa.From.Nick, contentStr)
	case "MESSAGE_CREATE":
		var m bot.MessageCreate
		if err := json.Unmarshal(data, &m); err != nil {
			log.Printf("[orca] bad MESSAGE_CREATE: %v", err)
			return
		}
		o.handleChannelMessage(ctx, m)
	}
}

// Start registers Orca with the registry and starts gateway connections.
// Call once at backend startup. `voiceAPI` may be nil; if provided, the
// voice subsystem uses an in-process SFU LocalParticipant tap instead
// of the default no-op.
func Start(ctx context.Context, irc IRC, voiceAPI LocalParticipantAPI) (*bot.Registry, error) {
	reg := bot.NewRegistry()
	o := New(irc)
	if o.token == "" {
		log.Printf("[orca] ORCA_PUSHBOT_TOKEN unset; Orca disabled")
		return reg, nil
	}
	if voiceAPI != nil {
		o.voiceTap = NewLocalTap(voiceAPI, o.nick)
	}
	reg.Register(o)
	gatewayURL := envOr("PUSHBOT_GATEWAY_URL", "ws://127.0.0.1:8600/pushbot/v1/gateway")
	if err := reg.StartAll(ctx, gatewayURL); err != nil {
		return nil, err
	}
	o.startVoice(ctx)
	log.Printf("[orca] started as %s, channels=%v, voice=%v, commands=[%s]",
		o.nick, o.channels, o.voiceChannels, bot.CommandNames(o.commands))
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

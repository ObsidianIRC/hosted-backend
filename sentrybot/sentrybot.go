// Package sentrybot exposes /sentry-* commands to opers so they can
// query the sentry daemon's state and supply ground-truth labels
// without leaving IRC. All HTTP traffic goes to the daemon's
// localhost admin API.
package sentrybot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"backend/bot"
)

// Bot is the IRC bot client. Implements bot.Bot.
type Bot struct {
	nick     string
	token    string
	channels []string
	prefix   string
	apiBase  string // http://127.0.0.1:9601
	http     *http.Client
}

// Start creates a Bot, registers it in a fresh bot.Registry, and
// starts the gateway connection. Mirrors orca.Start so main.go can
// wire both bots side by side.
func Start(ctx context.Context) (*bot.Registry, error) {
	reg := bot.NewRegistry()
	b := New()
	if b.token == "" {
		// Token unset means the operator doesn't want the bot to run.
		// Return an empty registry rather than an error so the rest
		// of hosted-backend isn't blocked.
		return reg, nil
	}
	reg.Register(b)
	gatewayURL := envDefault("PUSHBOT_GATEWAY_URL", "ws://127.0.0.1:8600/pushbot/v1/gateway")
	if err := reg.StartAll(ctx, gatewayURL); err != nil {
		return nil, err
	}
	return reg, nil
}

func New() *Bot {
	nick := envDefault("SENTRY_BOT_NICK", "Sentry")
	channels := strings.Split(envDefault("SENTRY_BOT_CHANNELS", "#opers"), ",")
	for i := range channels {
		channels[i] = strings.TrimSpace(channels[i])
	}
	return &Bot{
		nick:     nick,
		token:    os.Getenv("SENTRY_BOT_TOKEN"),
		channels: channels,
		prefix:   "!",
		apiBase:  envDefault("SENTRY_API_BASE", "http://127.0.0.1:9601"),
		http:     &http.Client{Timeout: 5 * time.Second},
	}
}

func (b *Bot) Nick() string        { return b.nick }
func (b *Bot) Token() string       { return b.token }
func (b *Bot) Channels() []string  { return b.channels }
func (b *Bot) Prefix() string      { return b.prefix }
func (b *Bot) OnEvent(_ context.Context, _ string, _ json.RawMessage) {}

func (b *Bot) Commands() []bot.Command {
	return []bot.Command{
		{
			Name: "sentry-status", Description: "show sentry pipeline stats",
			Contexts: []string{"channel", "private"},
		},
		{
			Name: "sentry-explain", Description: "show sentry's reasoning for a user",
			Contexts: []string{"channel", "private"},
			Options: []bot.Option{{Name: "nick", Type: "string", Required: true, Description: "nick of the user"}},
		},
		{
			Name: "sentry-label", Description: "tell sentry a flagged user is bad/good/ignore",
			Contexts: []string{"channel", "private"},
			Options: []bot.Option{
				{Name: "nick", Type: "string", Required: true},
				{Name: "verdict", Type: "string", Required: true, Choices: []string{"bad", "good", "ignore"}},
				{Name: "reason", Type: "string", Description: "free-text reason logged with the label"},
			},
		},
		{
			Name: "sentry-recent", Description: "show recent alerts sentry has emitted",
			Contexts: []string{"channel", "private"},
			Options: []bot.Option{{Name: "limit", Type: "integer", Description: "default 10, max 50"}},
		},
	}
}

func (b *Bot) OnInvoke(ctx context.Context, inv *bot.Invocation) error {
	switch inv.Command {
	case "sentry-status":
		return b.cmdStatus(ctx, inv)
	case "sentry-explain":
		return b.cmdExplain(ctx, inv)
	case "sentry-label":
		return b.cmdLabel(ctx, inv)
	case "sentry-recent":
		return b.cmdRecent(ctx, inv)
	default:
		return inv.Reply("unknown command")
	}
}

// --- handlers --------------------------------------------------------

func (b *Bot) cmdStatus(ctx context.Context, inv *bot.Invocation) error {
	var s struct {
		TrackedUsers int      `json:"tracked_users"`
		EventsTotal  int64    `json:"events_total"`
		AlertsTotal  int64    `json:"alerts_total"`
		RuleNames    []string `json:"rule_names"`
	}
	if err := b.getJSON(ctx, "/v1/stats", &s); err != nil {
		return inv.Reply("admin api unreachable: " + err.Error())
	}
	return inv.Reply(fmt.Sprintf(
		"users tracked: %d • events: %d • alerts: %d • L1 rules: %d (%s)",
		s.TrackedUsers, s.EventsTotal, s.AlertsTotal, len(s.RuleNames),
		strings.Join(s.RuleNames, ", "),
	))
}

func (b *Bot) cmdExplain(ctx context.Context, inv *bot.Invocation) error {
	nick := inv.String("nick")
	if nick == "" {
		return inv.Reply("nick is required")
	}
	var r struct {
		UID        string  `json:"UID"`
		Nick       string  `json:"Nick"`
		MaliceProb float64 `json:"MaliceProb"`
		Logit      float64 `json:"Logit"`
		Top        []struct {
			Feature string  `json:"Feature"`
			Value   float64 `json:"Value"`
			Weight  float64 `json:"Weight"`
			Contrib float64 `json:"Contrib"`
			ZScore  float64 `json:"ZScore"`
		} `json:"Top"`
		AnomalousZ []struct {
			Feature string  `json:"Feature"`
			Z       float64 `json:"Z"`
		} `json:"AnomalousZ"`
	}
	if err := b.getJSON(ctx, "/v1/explain?nick="+nick, &r); err != nil {
		return inv.Reply("explain failed: " + err.Error())
	}
	if r.Nick == "" {
		return inv.Reply("user " + nick + " not tracked")
	}
	// Stable top-5 listing.
	sort.SliceStable(r.Top, func(i, j int) bool {
		return absF(r.Top[i].Contrib) > absF(r.Top[j].Contrib)
	})
	lines := []string{
		fmt.Sprintf("sentry on %s (uid=%s): p=%.3f logit=%+.2f",
			r.Nick, r.UID, r.MaliceProb, r.Logit),
	}
	if len(r.AnomalousZ) > 0 {
		ans := make([]string, 0, len(r.AnomalousZ))
		for _, a := range r.AnomalousZ {
			ans = append(ans, fmt.Sprintf("%s(z=%.1f)", a.Feature, a.Z))
		}
		lines = append(lines, "L2 anomalies: "+strings.Join(ans, ", "))
	}
	for i, c := range r.Top {
		if i >= 5 {
			break
		}
		lines = append(lines, fmt.Sprintf("  %+.2f  %s (v=%.2f w=%.2f)",
			c.Contrib, c.Feature, c.Value, c.Weight))
	}
	return inv.Reply(strings.Join(lines, "\n"))
}

func (b *Bot) cmdLabel(ctx context.Context, inv *bot.Invocation) error {
	nick := inv.String("nick")
	verdict := inv.String("verdict")
	reason := inv.String("reason")
	if nick == "" || verdict == "" {
		return inv.Reply("usage: !sentry-label nick=<nick> verdict=<bad|good|ignore>")
	}
	body, _ := json.Marshal(map[string]string{
		"nick": nick, "verdict": verdict,
		"evidence": reason,
		"source":   "oper:" + inv.Author.Nick,
	})
	var resp struct {
		ID      int64  `json:"id"`
		Verdict string `json:"verdict"`
	}
	if err := b.postJSON(ctx, "/v1/label", body, &resp); err != nil {
		return inv.Reply("label failed: " + err.Error())
	}
	return inv.Reply(fmt.Sprintf("recorded label #%d (%s) for %s", resp.ID, resp.Verdict, nick))
}

func (b *Bot) cmdRecent(ctx context.Context, inv *bot.Invocation) error {
	limit := int(inv.Int("limit"))
	if limit <= 0 {
		limit = 10
	}
	if limit > 50 {
		limit = 50
	}
	var alerts []struct {
		Kind, UID, Nick, Channel string
		Confidence               float64
		Evidence                 string
	}
	if err := b.getJSON(ctx, fmt.Sprintf("/v1/recent-alerts?limit=%d", limit), &alerts); err != nil {
		return inv.Reply("recent failed: " + err.Error())
	}
	if len(alerts) == 0 {
		return inv.Reply("no recent alerts")
	}
	out := []string{fmt.Sprintf("last %d alerts:", len(alerts))}
	for _, a := range alerts {
		out = append(out, fmt.Sprintf("  %-22s %-12s conf=%.2f -- %s",
			a.Kind, a.Nick, a.Confidence, a.Evidence))
	}
	return inv.Reply(strings.Join(out, "\n"))
}

// --- http helpers ---------------------------------------------------

func (b *Bot) getJSON(ctx context.Context, path string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, b.apiBase+path, nil)
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return errors.New(strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (b *Bot) postJSON(ctx context.Context, path string, body []byte, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, b.apiBase+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return errors.New(strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func envDefault(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func absF(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

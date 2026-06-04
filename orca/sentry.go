package orca

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

var sentryStatusCommand = bot.Command{
	Name:        "sentry-status",
	Description: "Sentry pipeline stats: tracked users, events, alerts, active L1 rule names.",
	Contexts:    []string{"channel", "private"},
}

var sentryExplainCommand = bot.Command{
	Name:        "sentry-explain",
	Description: "Show Sentry's reasoning for a user: malice probability, top feature contributions, L2 anomalies.",
	Contexts:    []string{"channel", "private"},
	Options: []bot.Option{
		{Name: "nick", Type: "string", Required: true, Description: "Nick of the user to explain."},
	},
}

var sentryLabelCommand = bot.Command{
	Name:        "sentry-label",
	Description: "Record an operator verdict on a user (bad/good/ignore) and train the L3 classifier.",
	Contexts:    []string{"channel", "private"},
	Options: []bot.Option{
		{Name: "nick", Type: "string", Required: true},
		{Name: "verdict", Type: "string", Required: true, Choices: []string{"bad", "good", "ignore"}},
		{Name: "reason", Type: "string", Description: "Free-text reason logged with the label."},
	},
}

var sentryRecentCommand = bot.Command{
	Name:        "sentry-recent",
	Description: "Show the last N alerts Sentry has emitted.",
	Contexts:    []string{"channel", "private"},
	Options: []bot.Option{
		{Name: "limit", Type: "integer", Description: "Default 10, max 50."},
	},
}

func sentryAPIBase() string {
	if v := os.Getenv("SENTRY_API_BASE"); v != "" {
		return v
	}
	return "http://127.0.0.1:9601"
}

var sentryHTTP = &http.Client{Timeout: 5 * time.Second}

func sentryGetJSON(ctx context.Context, path string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, sentryAPIBase()+path, nil)
	resp, err := sentryHTTP.Do(req)
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

func sentryPostJSON(ctx context.Context, path string, body []byte, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, sentryAPIBase()+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := sentryHTTP.Do(req)
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

func (o *Orca) cmdSentryStatus(ctx context.Context, inv *bot.Invocation) error {
	var s struct {
		TrackedUsers int      `json:"tracked_users"`
		EventsTotal  int64    `json:"events_total"`
		AlertsTotal  int64    `json:"alerts_total"`
		RuleNames    []string `json:"rule_names"`
	}
	if err := sentryGetJSON(ctx, "/v1/stats", &s); err != nil {
		return inv.Reply("sentry admin api unreachable: " + err.Error())
	}
	return inv.Reply(fmt.Sprintf(
		"users tracked: %d • events: %d • alerts: %d • L1 rules (%d): %s",
		s.TrackedUsers, s.EventsTotal, s.AlertsTotal, len(s.RuleNames),
		strings.Join(s.RuleNames, ", "),
	))
}

func (o *Orca) cmdSentryExplain(ctx context.Context, inv *bot.Invocation) error {
	nick := strings.TrimSpace(inv.String("nick"))
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
	if err := sentryGetJSON(ctx, "/v1/explain?nick="+nick, &r); err != nil {
		return inv.Reply("sentry-explain failed: " + err.Error())
	}
	if r.Nick == "" {
		return inv.Reply("user " + nick + " not tracked by Sentry")
	}
	sort.SliceStable(r.Top, func(i, j int) bool {
		return abs64(r.Top[i].Contrib) > abs64(r.Top[j].Contrib)
	})
	lines := []string{
		fmt.Sprintf("Sentry on %s (uid=%s): p=%.3f logit=%+.2f",
			r.Nick, r.UID, r.MaliceProb, r.Logit),
	}
	if len(r.AnomalousZ) > 0 {
		parts := make([]string, 0, len(r.AnomalousZ))
		for _, a := range r.AnomalousZ {
			parts = append(parts, fmt.Sprintf("%s(z=%.1f)", a.Feature, a.Z))
		}
		lines = append(lines, "L2 anomalies: "+strings.Join(parts, ", "))
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

func (o *Orca) cmdSentryLabel(ctx context.Context, inv *bot.Invocation) error {
	nick := strings.TrimSpace(inv.String("nick"))
	verdict := strings.TrimSpace(inv.String("verdict"))
	reason := inv.String("reason")
	if nick == "" || verdict == "" {
		return inv.Reply("usage: !sentry-label nick=<nick> verdict=<bad|good|ignore>")
	}
	body, _ := json.Marshal(map[string]string{
		"nick":     nick,
		"verdict":  verdict,
		"evidence": reason,
		"source":   "oper:" + inv.Author.Nick,
	})
	var resp struct {
		ID      int64  `json:"id"`
		Verdict string `json:"verdict"`
	}
	if err := sentryPostJSON(ctx, "/v1/label", body, &resp); err != nil {
		return inv.Reply("sentry-label failed: " + err.Error())
	}
	return inv.Reply(fmt.Sprintf("recorded label #%d (%s) for %s", resp.ID, resp.Verdict, nick))
}

func (o *Orca) cmdSentryRecent(ctx context.Context, inv *bot.Invocation) error {
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
	if err := sentryGetJSON(ctx, fmt.Sprintf("/v1/recent-alerts?limit=%d", limit), &alerts); err != nil {
		return inv.Reply("sentry-recent failed: " + err.Error())
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

func abs64(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

package orca

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"backend/bot"
)

var scanCommand = bot.Command{
	Name:        "scan",
	Description: "Multi-step risk scan of a channel's members (oper-only).",
	Contexts:    []string{"pm", "private"},
	Options: []bot.Option{
		{Name: "channel", Type: "channel", Required: true,
			Description: "Channel to scan."},
	},
}

type scanFinding struct {
	nick    string
	flags   []string
	score   int
}

func (o *Orca) cmdScan(ctx context.Context, inv *bot.Invocation) error {
	_ = inv.Defer()
	channel := strings.TrimSpace(inv.String("channel"))
	if channel == "" {
		return inv.Whisper("scan: channel required.")
	}
	w := inv.NewWorkflow("scan " + channel)
	if err := w.Start("interactive", "reasoning"); err != nil {
		return err
	}

	tool := newIRCTool(o.irc)

	st := w.StartToolCall("channel-get", "Fetch member list",
		map[string]any{"channel": channel})
	ch, err := tool.ChannelGet(ctx, channel, 2)
	if err != nil {
		_ = st.Failed(err.Error())
		_ = w.Failed()
		return inv.Whisper("scan: " + err.Error())
	}
	if ch == nil {
		_ = st.Failed("channel not found")
		_ = w.Failed()
		return inv.Whisper("scan: channel " + channel + " not found.")
	}
	members := toMapList(ch, "members")
	_ = st.Result(fmt.Sprintf("%d members", len(members)))

	hostCount := map[string]int{}
	acctCount := map[string]int{}
	findings := []scanFinding{}

	checked := 0
	for _, m := range members {
		nick := getString(m, "name")
		if nick == "" {
			continue
		}
		checked++
		fst := w.StartToolCall("user-get",
			fmt.Sprintf("Check %s (%d/%d)", nick, checked, len(members)),
			map[string]any{"nick": nick})
		u, err := tool.UserGet(ctx, nick, 3)
		if err != nil || u == nil {
			_ = fst.Failed("missing")
			continue
		}
		_ = fst.Result("ok")

		host := getString(u, "hostname")
		acct := getString(u, "user", "account")
		if host != "" {
			hostCount[host]++
		}
		if acct != "" && acct != "*" {
			acctCount[acct]++
		}

		f := scanFinding{nick: nick}
		if acct == "" || acct == "*" {
			f.flags = append(f.flags, "no-account")
			f.score += 1
		}
		if conn := getString(u, "connected_since"); conn != "" {
			if t, perr := time.Parse(time.RFC3339, conn); perr == nil {
				if time.Since(t) < 5*time.Minute {
					f.flags = append(f.flags, "fresh-connect")
					f.score += 2
				}
			}
		}
		if getString(u, "tls", "cipher") == "" {
			f.flags = append(f.flags, "plaintext")
			f.score += 1
		}
		if certfp := getString(u, "tls", "certfp"); certfp == "" {
			f.flags = append(f.flags, "no-certfp")
		}
		if len(f.flags) > 0 {
			findings = append(findings, f)
		}
	}

	// Pivot: shared host or account collisions.
	hostHits := []string{}
	for h, n := range hostCount {
		if n >= 2 {
			hostHits = append(hostHits, fmt.Sprintf("%s (x%d)", h, n))
		}
	}
	acctHits := []string{}
	for a, n := range acctCount {
		if n >= 2 {
			acctHits = append(acctHits, fmt.Sprintf("%s (x%d)", a, n))
		}
	}
	if len(hostHits) > 0 || len(acctHits) > 0 {
		_ = w.Reasoning(fmt.Sprintf("collisions: hosts=%d, accounts=%d",
			len(hostHits), len(acctHits)))
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].score > findings[j].score
	})

	var b strings.Builder
	fmt.Fprintf(&b, "scan %s: %d members, %d flagged\n",
		channel, len(members), len(findings))
	if len(hostHits) > 0 {
		fmt.Fprintf(&b, "  shared hosts:    %s\n", strings.Join(hostHits, ", "))
	}
	if len(acctHits) > 0 {
		fmt.Fprintf(&b, "  shared accounts: %s\n", strings.Join(acctHits, ", "))
	}
	top := findings
	if len(top) > 10 {
		top = top[:10]
	}
	for _, f := range top {
		fmt.Fprintf(&b, "  %s — %s\n", f.nick, strings.Join(f.flags, ","))
	}
	if len(findings) > len(top) {
		fmt.Fprintf(&b, "  ... %d more\n", len(findings)-len(top))
	}

	_ = w.Complete()
	return inv.Whisper(strings.TrimRight(b.String(), "\n"))
}

package orca

import (
	"context"
	"fmt"
	"net"
	"strings"

	"backend/bot"
)

var synthBanCommand = bot.Command{
	Name:        "synth-ban",
	Description: "Suggest the most specific ban mask that catches a target with minimal collateral.",
	Contexts:    []string{"pm", "private"},
	Options: []bot.Option{
		{Name: "nick", Type: "user", Required: true,
			Description: "User to synthesize a ban for."},
		{Name: "scope", Type: "string", Required: false,
			Description: "channel (default) or netwide.",
			Choices: []string{"channel", "netwide"}},
	},
}

type maskCandidate struct {
	mask    string
	reason  string
	matches int
	specificity int
}

func (o *Orca) cmdSynthBan(ctx context.Context, inv *bot.Invocation) error {
	_ = inv.Defer()
	nick := strings.TrimSpace(inv.String("nick"))
	if nick == "" {
		return inv.Whisper("synth-ban: nick required.")
	}
	scope := inv.String("scope")
	if scope == "" {
		scope = "channel"
	}

	w := inv.NewWorkflow("synth-ban " + nick)
	if err := w.Start("interactive", "reasoning"); err != nil {
		return err
	}

	tool := newIRCTool(o.irc)
	st := w.StartToolCall("user-get", "Fetch target", map[string]any{"nick": nick})
	u, err := tool.UserGet(ctx, nick, 4)
	if err != nil || u == nil {
		_ = st.Failed("target not online")
		_ = w.Failed()
		return inv.Whisper("synth-ban: " + nick + " not online (need them online to inspect).")
	}
	_ = st.Result("ok")

	acct := getString(u, "user", "account")
	certfp := getString(u, "tls", "certfp")
	host := getString(u, "hostname")
	ip := getString(u, "ip")
	uName := getString(u, "user", "username")

	_ = w.Reasoning(fmt.Sprintf("anchors: account=%q certfp=%q host=%q ip=%q user=%q",
		acct, certfp, host, ip, uName))

	scanSt := w.StartToolCall("user-list",
		"Cross-check candidates against userbase", nil)
	all, err := tool.UserList(ctx, 3)
	if err != nil {
		_ = scanSt.Failed(err.Error())
		_ = w.Failed()
		return inv.Whisper("synth-ban: " + err.Error())
	}
	_ = scanSt.Result(fmt.Sprintf("%d users", len(all)))

	cands := []maskCandidate{}

	if certfp != "" {
		mask := "~certfp:" + certfp
		cands = append(cands, maskCandidate{
			mask:        mask,
			reason:      "TLS client cert fingerprint (stable, ban-proof)",
			matches:     countMatches(parseMask(mask), all),
			specificity: 100,
		})
	}
	if acct != "" && acct != "*" {
		mask := "~account:" + acct
		cands = append(cands, maskCandidate{
			mask:        mask,
			reason:      "registered account (stable, ban-proof if account survives)",
			matches:     countMatches(parseMask(mask), all),
			specificity: 80,
		})
	}
	if ip != "" {
		mask := "~cidr:" + ip + "/32"
		cands = append(cands, maskCandidate{
			mask:        mask,
			reason:      "exact IP",
			matches:     countMatches(parseMask(mask), all),
			specificity: 70,
		})
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			if v4 := parsedIP.To4(); v4 != nil {
				cidr := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
				cmask := "~cidr:" + cidr
				cands = append(cands, maskCandidate{
					mask:        cmask,
					reason:      "/24 around the IP",
					matches:     countMatches(parseMask(cmask), all),
					specificity: 50,
				})
			}
		}
	}
	if host != "" && host != ip {
		mask := "*!*@" + host
		cands = append(cands, maskCandidate{
			mask:        mask,
			reason:      "exact host",
			matches:     countMatches(parseMask(mask), all),
			specificity: 60,
		})
	}
	// last-resort: nick!user@host as upstream emits it.
	if host != "" {
		full := nick + "!" + uName + "@" + host
		cands = append(cands, maskCandidate{
			mask:        full,
			reason:      "full nick!user@host (loose: nick is mutable)",
			matches:     countMatches(parseMask(full), all),
			specificity: 30,
		})
	}

	// Rank: prefer high-specificity AND low collateral.
	bestIdx := -1
	for i, c := range cands {
		if c.matches == 0 || c.matches > 1 {
			continue
		}
		if bestIdx < 0 || cands[i].specificity > cands[bestIdx].specificity {
			bestIdx = i
		}
	}
	if bestIdx < 0 {
		// fall back to the tightest non-empty candidate.
		for i, c := range cands {
			if c.matches == 0 {
				continue
			}
			if bestIdx < 0 || c.matches < cands[bestIdx].matches {
				bestIdx = i
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "synth-ban %s (%s scope)\n", nick, scope)
	if bestIdx >= 0 {
		c := cands[bestIdx]
		fmt.Fprintf(&b, "  recommended: %s\n", c.mask)
		fmt.Fprintf(&b, "  reason:      %s\n", c.reason)
		fmt.Fprintf(&b, "  collateral:  %d other matching user(s)\n", c.matches-1)
	} else {
		fmt.Fprintf(&b, "  could not synthesize a precise mask.\n")
	}
	fmt.Fprintf(&b, "  candidates:\n")
	for _, c := range cands {
		extra := ""
		if c.matches > 1 {
			extra = fmt.Sprintf(" (+%d collateral)", c.matches-1)
		}
		fmt.Fprintf(&b, "    - %s  -- %s%s\n", c.mask, c.reason, extra)
	}

	_ = w.Complete()
	return inv.Whisper(strings.TrimRight(b.String(), "\n"))
}

func countMatches(p parsedMask, users []map[string]any) int {
	n := 0
	for _, u := range users {
		if p.matches(u) {
			n++
		}
	}
	return n
}

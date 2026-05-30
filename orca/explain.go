package orca

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"backend/bot"
)

var explainCommand = bot.Command{
	Name:        "explain",
	Description: "Walk the userbase and report what a ban/extban/k-line mask actually matches.",
	Contexts:    []string{"pm", "private"},
	Options: []bot.Option{
		{Name: "mask", Type: "string", Required: true,
			Description: "Ban or extban mask to explain."},
	},
}

func (o *Orca) cmdExplain(ctx context.Context, inv *bot.Invocation) error {
	maskStr := strings.TrimSpace(inv.String("mask"))
	if maskStr == "" {
		return inv.Whisper("explain: mask required.")
	}
	w := inv.NewWorkflow("explain " + maskStr)
	if err := w.Start("interactive", "reasoning"); err != nil {
		return err
	}

	parsed := parseMask(maskStr)
	_ = w.Reasoning("parsed mask: " + parsed.describe())

	if parsed.kind == maskUnknown {
		_ = w.Failed()
		return inv.Whisper("explain: could not parse mask " + maskStr +
			"\n(supported: nick!user@host, CIDR, ~account: / ~certfp: / ~realname: / ~country:)")
	}

	tool := newIRCTool(o.irc)
	st := w.StartToolCall("user-list", "Fetch current userbase", map[string]any{})
	users, err := tool.UserList(ctx, 3)
	if err != nil {
		_ = st.Failed(err.Error())
		_ = w.Failed()
		return inv.Whisper("explain: " + err.Error())
	}
	_ = st.Result(fmt.Sprintf("%d users", len(users)))

	matched := []string{}
	for _, u := range users {
		if parsed.matches(u) {
			matched = append(matched, getString(u, "name"))
		}
	}
	sort.Strings(matched)

	_ = w.Reasoning(fmt.Sprintf("scanned %d users, %d matched",
		len(users), len(matched)))

	var b strings.Builder
	fmt.Fprintf(&b, "explain %s\n", maskStr)
	fmt.Fprintf(&b, "  kind:    %s\n", parsed.describe())
	fmt.Fprintf(&b, "  scanned: %d users\n", len(users))
	fmt.Fprintf(&b, "  matches: %d\n", len(matched))
	if len(matched) > 0 {
		preview := matched
		if len(preview) > 25 {
			preview = preview[:25]
		}
		fmt.Fprintf(&b, "  who:     %s\n", strings.Join(preview, " "))
		if len(matched) > len(preview) {
			fmt.Fprintf(&b, "  ... (%d more)\n", len(matched)-len(preview))
		}
	}
	if parsed.kind == maskNickUserHost && parsed.host == "*" {
		fmt.Fprintf(&b, "  warning: host=* matches every user; almost certainly too broad.\n")
	}
	if len(matched) > 5 && parsed.kind == maskNickUserHost {
		fmt.Fprintf(&b, "  warning: %d users matched -- consider tightening (account/certfp/cidr).\n", len(matched))
	}

	_ = w.Complete()
	return inv.Whisper(strings.TrimRight(b.String(), "\n"))
}

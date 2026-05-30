package orca

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"backend/bot"
)

var auditCommand = bot.Command{
	Name:        "audit",
	Description: "Timeline summary for a user or channel (oper-only).",
	Contexts:    []string{"pm", "private"},
	Options: []bot.Option{
		{Name: "target", Type: "string", Required: true,
			Description: "Nick or channel to audit."},
	},
}

func (o *Orca) cmdAudit(ctx context.Context, inv *bot.Invocation) error {
	target := strings.TrimSpace(inv.String("target"))
	if target == "" {
		return inv.Whisper("audit: target required.")
	}
	w := inv.NewWorkflow("audit " + target)
	if err := w.Start("interactive", "reasoning"); err != nil {
		return err
	}

	tool := newIRCTool(o.irc)
	isChannel := strings.HasPrefix(target, "#") ||
		strings.HasPrefix(target, "&") ||
		strings.HasPrefix(target, "^")

	if isChannel {
		st := w.StartToolCall("channel-get", "Fetch channel state", map[string]any{"channel": target})
		ch, err := tool.ChannelGet(ctx, target, 4)
		if err != nil {
			_ = st.Failed(err.Error())
			_ = w.Failed()
			return inv.Whisper("audit: " + err.Error())
		}
		_ = st.Result(fmt.Sprintf("ok: %s, %d users",
			getString(ch, "name"), len(toMapList(ch, "members"))))

		out := o.renderChannelAudit(ch)
		_ = w.Complete()
		return inv.Whisper(out)
	}

	st := w.StartToolCall("user-get", "Fetch user state", map[string]any{"nick": target})
	u, err := tool.UserGet(ctx, target, 4)
	if err != nil {
		_ = st.Failed(err.Error())
		_ = w.Failed()
		return inv.Whisper("audit: " + err.Error())
	}
	if u == nil {
		_ = st.Failed("not online")
		_ = w.Failed()
		return inv.Whisper("audit: " + target + " not online.")
	}
	_ = st.Result(fmt.Sprintf("ok: %s @ %s",
		getString(u, "name"), getString(u, "hostname")))

	out := o.renderUserAudit(u)
	_ = w.Complete()
	return inv.Whisper(out)
}

func (o *Orca) renderUserAudit(u map[string]any) string {
	var b strings.Builder
	nick := getString(u, "name")
	fmt.Fprintf(&b, "audit %s\n", nick)
	fmt.Fprintf(&b, "  ident@host:    %s@%s\n",
		getString(u, "user", "username"), getString(u, "hostname"))
	if ip := getString(u, "ip"); ip != "" {
		fmt.Fprintf(&b, "  real ip:       %s\n", ip)
	}
	if acct := getString(u, "user", "account"); acct != "" && acct != "*" {
		fmt.Fprintf(&b, "  account:       %s\n", acct)
	} else {
		fmt.Fprintf(&b, "  account:       (not logged in)\n")
	}
	if certfp := getString(u, "tls", "certfp"); certfp != "" {
		fmt.Fprintf(&b, "  certfp:        %s\n", certfp)
	}
	if cn := getString(u, "tls", "cipher"); cn != "" {
		fmt.Fprintf(&b, "  tls:           %s\n", cn)
	}
	if modes := getString(u, "user", "modes"); modes != "" {
		fmt.Fprintf(&b, "  modes:         +%s\n", modes)
	}
	if conn := getString(u, "connected_since"); conn != "" {
		fmt.Fprintf(&b, "  connected:     %s%s\n", conn, sinceParens(conn))
	}
	if idle := getInt(u, "idle"); idle > 0 {
		fmt.Fprintf(&b, "  idle:          %s\n", humanDuration(time.Duration(idle)*time.Second))
	}
	if chans := getStringList(u, "user", "channels"); len(chans) > 0 {
		fmt.Fprintf(&b, "  channels (%d): %s\n", len(chans), strings.Join(chans, " "))
	}
	if server := getString(u, "user", "servername"); server != "" {
		fmt.Fprintf(&b, "  on server:     %s\n", server)
	}
	if getBool(u, "user", "operlogin") || getString(u, "user", "operlogin") != "" {
		fmt.Fprintf(&b, "  oper login:    %s\n", getString(u, "user", "operlogin"))
	}
	return strings.TrimRight(b.String(), "\n")
}

func (o *Orca) renderChannelAudit(ch map[string]any) string {
	var b strings.Builder
	name := getString(ch, "name")
	fmt.Fprintf(&b, "audit %s\n", name)
	if modes := getString(ch, "modes"); modes != "" {
		fmt.Fprintf(&b, "  modes:    +%s\n", modes)
	}
	if topic := getString(ch, "topic"); topic != "" {
		setBy := getString(ch, "topic_set_by")
		setAt := getString(ch, "topic_set_at")
		fmt.Fprintf(&b, "  topic:    %s\n", topic)
		if setBy != "" {
			fmt.Fprintf(&b, "  set by:   %s %s\n", setBy, setAt)
		}
	}
	fmt.Fprintf(&b, "  created:  %s%s\n",
		getString(ch, "creation_time"),
		sinceParens(getString(ch, "creation_time")))
	members := toMapList(ch, "members")
	fmt.Fprintf(&b, "  members:  %d\n", len(members))
	bans := toMapList(ch, "bans")
	if len(bans) > 0 {
		fmt.Fprintf(&b, "  bans:     %d\n", len(bans))
	}
	excepts := toMapList(ch, "ban_exemptions")
	if len(excepts) > 0 {
		fmt.Fprintf(&b, "  excepts:  %d\n", len(excepts))
	}
	invex := toMapList(ch, "invite_exceptions")
	if len(invex) > 0 {
		fmt.Fprintf(&b, "  invex:    %d\n", len(invex))
	}

	// Brief member roster: nick(roles).
	if len(members) > 0 {
		names := make([]string, 0, len(members))
		for _, m := range members {
			nick := getString(m, "name")
			role := strings.TrimSpace(getString(m, "level"))
			if role != "" {
				nick += "(" + role + ")"
			}
			names = append(names, nick)
		}
		sort.Strings(names)
		fmt.Fprintf(&b, "  roster:   %s\n", strings.Join(names, " "))
	}
	return strings.TrimRight(b.String(), "\n")
}

func sinceParens(iso string) string {
	if iso == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05", iso)
		if err != nil {
			return ""
		}
	}
	return " (" + humanDuration(time.Since(t)) + " ago)"
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	return fmt.Sprintf("%dd%dh", days, int(d.Hours())%24)
}

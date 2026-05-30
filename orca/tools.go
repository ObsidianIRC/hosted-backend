package orca

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"backend/ai"
	"backend/bot"
)

type Tool struct {
	Name        string
	Description string
	Parameters  map[string]any
	Handler     func(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error)
}

func (o *Orca) aiTools() []ai.ToolSpec {
	o.cmdMu.RLock()
	defer o.cmdMu.RUnlock()
	out := make([]ai.ToolSpec, 0, len(o.aiToolMap))
	names := make([]string, 0, len(o.aiToolMap))
	for n := range o.aiToolMap {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := o.aiToolMap[n]
		out = append(out, ai.ToolSpec{
			Type: "function",
			Function: ai.FunctionSpec{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.Parameters,
			},
		})
	}
	return out
}

func (o *Orca) registerTool(t Tool) {
	if o.aiToolMap == nil {
		o.aiToolMap = map[string]Tool{}
	}
	o.aiToolMap[t.Name] = t
}

func (o *Orca) registerDefaultTools() {
	o.registerTool(Tool{
		Name:        "user_get",
		Description: "Get full detail about a single user by nick.",
		Parameters: objectSchema(
			prop("nick", "string", "Nickname to look up."),
		).required("nick").build(),
		Handler: toolUserGet,
	})
	o.registerTool(Tool{
		Name:        "user_list",
		Description: "List all users on the network. Returns nick, host, account, idle for each.",
		Parameters:  objectSchema().build(),
		Handler:     toolUserList,
	})
	o.registerTool(Tool{
		Name:        "channel_get",
		Description: "Get full detail about a channel by name, including members, bans, and topic.",
		Parameters: objectSchema(
			prop("channel", "string", "Channel name including its prefix (e.g. #opers)."),
		).required("channel").build(),
		Handler: toolChannelGet,
	})
	o.registerTool(Tool{
		Name:        "channel_list",
		Description: "List all channels on the network with size and modes.",
		Parameters:  objectSchema().build(),
		Handler:     toolChannelList,
	})
	o.registerTool(Tool{
		Name:        "bans_list",
		Description: "List server-side bans (K-lines / G-lines).",
		Parameters:  objectSchema().build(),
		Handler:     toolBansList,
	})
	o.registerTool(Tool{
		Name:        "stats",
		Description: "Get server statistics (connections, channels, opers, etc.).",
		Parameters:  objectSchema().build(),
		Handler:     toolStats,
	})
	o.registerTool(Tool{
		Name:        "explain_mask",
		Description: "Walk current users and report what a ban/extban/k-line mask matches. Useful for validating before applying.",
		Parameters: objectSchema(
			prop("mask", "string", "Ban mask, extban, or CIDR."),
		).required("mask").build(),
		Handler: toolExplainMask,
	})
}

func toolUserGet(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	nick, _ := params["nick"].(string)
	if nick == "" {
		return "", fmt.Errorf("nick required")
	}
	st := w.StartToolCall("user-get", "Look up "+nick, params)
	u, err := newIRCTool(o.irc).UserGet(ctx, nick, 4)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	if u == nil {
		_ = st.Result("not online")
		return "{}  // user not online", nil
	}
	b, _ := json.Marshal(u)
	_ = st.Result(truncate(string(b), 240))
	return string(b), nil
}

func toolUserList(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("user-list", "List all users", nil)
	users, err := newIRCTool(o.irc).UserList(ctx, 2)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, map[string]any{
			"nick":    getString(u, "name"),
			"host":    getString(u, "hostname"),
			"ip":      getString(u, "ip"),
			"account": getString(u, "user", "account"),
		})
	}
	b, _ := json.Marshal(out)
	_ = st.Result(fmt.Sprintf("%d users", len(out)))
	return string(b), nil
}

func toolChannelGet(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	channel, _ := params["channel"].(string)
	if channel == "" {
		return "", fmt.Errorf("channel required")
	}
	st := w.StartToolCall("channel-get", "Look up "+channel, params)
	ch, err := newIRCTool(o.irc).ChannelGet(ctx, channel, 4)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	if ch == nil {
		_ = st.Result("not found")
		return "{}", nil
	}
	b, _ := json.Marshal(ch)
	_ = st.Result(fmt.Sprintf("ok: %d members",
		len(toMapList(ch, "members"))))
	return string(b), nil
}

func toolChannelList(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("channel-list", "List all channels", nil)
	chans, err := newIRCTool(o.irc).ChannelList(ctx, 1)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	out := make([]map[string]any, 0, len(chans))
	for _, c := range chans {
		out = append(out, map[string]any{
			"name":  getString(c, "name"),
			"size":  getInt(c, "num_users"),
			"modes": getString(c, "modes"),
		})
	}
	b, _ := json.Marshal(out)
	_ = st.Result(fmt.Sprintf("%d channels", len(out)))
	return string(b), nil
}

func toolBansList(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("bans-list", "List server bans", nil)
	bans, err := newIRCTool(o.irc).BansList(ctx)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	b, _ := json.Marshal(bans)
	_ = st.Result(fmt.Sprintf("%d bans", len(bans)))
	return string(b), nil
}

func toolStats(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	st := w.StartToolCall("stats", "Server stats", nil)
	s, err := newIRCTool(o.irc).Stats(ctx)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	b, _ := json.Marshal(s)
	_ = st.Result("ok")
	return string(b), nil
}

func toolExplainMask(ctx context.Context, o *Orca, params map[string]any, w *bot.WorkflowEmitter) (string, error) {
	maskStr, _ := params["mask"].(string)
	if maskStr == "" {
		return "", fmt.Errorf("mask required")
	}
	st := w.StartToolCall("explain-mask", "Walk users vs mask", params)
	parsed := parseMask(maskStr)
	if parsed.kind == maskUnknown {
		_ = st.Failed("unparseable")
		return `{"error":"could not parse mask"}`, nil
	}
	users, err := newIRCTool(o.irc).UserList(ctx, 2)
	if err != nil {
		_ = st.Failed(err.Error())
		return "", err
	}
	matched := []string{}
	for _, u := range users {
		if parsed.matches(u) {
			matched = append(matched, getString(u, "name"))
		}
	}
	res := map[string]any{
		"mask":     maskStr,
		"kind":     parsed.describe(),
		"scanned":  len(users),
		"matches":  len(matched),
		"matched":  matched,
	}
	b, _ := json.Marshal(res)
	_ = st.Result(fmt.Sprintf("%d/%d matched", len(matched), len(users)))
	return string(b), nil
}

// objectSchema is a tiny builder for OpenAI-style function parameter JSON Schema.
type schemaBuilder struct {
	props      map[string]any
	requireds  []string
}

func objectSchema(props ...map[string]any) *schemaBuilder {
	b := &schemaBuilder{props: map[string]any{}}
	for _, p := range props {
		for k, v := range p {
			b.props[k] = v
		}
	}
	return b
}

func prop(name, jsonType, desc string) map[string]any {
	return map[string]any{
		name: map[string]any{"type": jsonType, "description": desc},
	}
}

func (b *schemaBuilder) required(names ...string) *schemaBuilder {
	b.requireds = append(b.requireds, names...)
	return b
}

func (b *schemaBuilder) build() map[string]any {
	out := map[string]any{
		"type":       "object",
		"properties": b.props,
	}
	if len(b.requireds) > 0 {
		out["required"] = b.requireds
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func toolNameList(m map[string]Tool) string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

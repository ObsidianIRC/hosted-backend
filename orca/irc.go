package orca

import (
	"context"
	"errors"
	"fmt"
)

type IRC interface {
	Query(ctx context.Context, method string, params map[string]any) (any, error)
}

type ircTool struct {
	irc IRC
}

func newIRCTool(irc IRC) *ircTool { return &ircTool{irc: irc} }

func (t *ircTool) UserGet(ctx context.Context, nick string, detail int) (map[string]any, error) {
	if t.irc == nil {
		return nil, errors.New("no IRC connection")
	}
	res, err := t.irc.Query(ctx, "user.get", map[string]any{
		"nick":                nick,
		"object_detail_level": detail,
	})
	if err != nil {
		return nil, err
	}
	if m, ok := res.(map[string]any); ok {
		if c, ok := m["client"].(map[string]any); ok {
			return c, nil
		}
		return m, nil
	}
	return nil, fmt.Errorf("unexpected user.get result")
}

func (t *ircTool) UserList(ctx context.Context, detail int) ([]map[string]any, error) {
	if t.irc == nil {
		return nil, errors.New("no IRC connection")
	}
	res, err := t.irc.Query(ctx, "user.list", map[string]any{
		"object_detail_level": detail,
	})
	if err != nil {
		return nil, err
	}
	return toMapList(res, "list"), nil
}

func (t *ircTool) ChannelGet(ctx context.Context, name string, detail int) (map[string]any, error) {
	if t.irc == nil {
		return nil, errors.New("no IRC connection")
	}
	res, err := t.irc.Query(ctx, "channel.get", map[string]any{
		"channel":             name,
		"object_detail_level": detail,
	})
	if err != nil {
		return nil, err
	}
	if m, ok := res.(map[string]any); ok {
		if c, ok := m["channel"].(map[string]any); ok {
			return c, nil
		}
		return m, nil
	}
	return nil, fmt.Errorf("unexpected channel.get result")
}

func (t *ircTool) ChannelList(ctx context.Context, detail int) ([]map[string]any, error) {
	if t.irc == nil {
		return nil, errors.New("no IRC connection")
	}
	res, err := t.irc.Query(ctx, "channel.list", map[string]any{
		"object_detail_level": detail,
	})
	if err != nil {
		return nil, err
	}
	return toMapList(res, "list"), nil
}

func (t *ircTool) BansList(ctx context.Context) ([]map[string]any, error) {
	if t.irc == nil {
		return nil, errors.New("no IRC connection")
	}
	res, err := t.irc.Query(ctx, "server_ban.list", nil)
	if err != nil {
		return nil, err
	}
	return toMapList(res, "list"), nil
}

// --- Admin actions (destructive RPC calls) -------------------------------

func (t *ircTool) UserKill(ctx context.Context, nick, reason string) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	_, err := t.irc.Query(ctx, "user.kill", map[string]any{
		"nick":   nick,
		"reason": reason,
	})
	return err
}

func (t *ircTool) ChannelKick(ctx context.Context, channel, nick, reason string) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	_, err := t.irc.Query(ctx, "channel.kick", map[string]any{
		"channel": channel,
		"nick":    nick,
		"reason":  reason,
	})
	return err
}

func (t *ircTool) ChannelSetTopic(ctx context.Context, channel, topic string) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	_, err := t.irc.Query(ctx, "channel.set_topic", map[string]any{
		"channel": channel,
		"topic":   topic,
	})
	return err
}

func (t *ircTool) ChannelSetMode(ctx context.Context, channel, modes, parameters string) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	_, err := t.irc.Query(ctx, "channel.set_mode", map[string]any{
		"channel":    channel,
		"modes":      modes,
		"parameters": parameters,
	})
	return err
}

// BanAdd applies a server-wide ban. `banType` is the UnrealIRCd
// type-name (gline / kline / zline / gzline / shun / spamfilter).
// `name` is the mask (e.g. *@bad.example.com or user@*).
// duration "" = permanent; UnrealIRCd time format ("1d", "30m", etc.)
func (t *ircTool) BanAdd(ctx context.Context, banType, name, reason, duration string) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	p := map[string]any{
		"name":   name,
		"type":   banType,
		"reason": reason,
	}
	if duration != "" {
		p["duration_string"] = duration
	}
	_, err := t.irc.Query(ctx, "server_ban.add", p)
	return err
}

func (t *ircTool) BanDel(ctx context.Context, banType, name string) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	_, err := t.irc.Query(ctx, "server_ban.del", map[string]any{
		"name": name,
		"type": banType,
	})
	return err
}

func (t *ircTool) NickBanAdd(ctx context.Context, name, reason, duration string) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	p := map[string]any{
		"name":   name,
		"reason": reason,
	}
	if duration != "" {
		p["duration_string"] = duration
	}
	_, err := t.irc.Query(ctx, "name_ban.add", p)
	return err
}

func (t *ircTool) NickBanDel(ctx context.Context, name string) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	_, err := t.irc.Query(ctx, "name_ban.del", map[string]any{
		"name": name,
	})
	return err
}

func (t *ircTool) ServerRehash(ctx context.Context) error {
	if t.irc == nil {
		return errors.New("no IRC connection")
	}
	_, err := t.irc.Query(ctx, "server.rehash", nil)
	return err
}

func (t *ircTool) ServerList(ctx context.Context) ([]map[string]any, error) {
	if t.irc == nil {
		return nil, errors.New("no IRC connection")
	}
	res, err := t.irc.Query(ctx, "server.list", nil)
	if err != nil {
		return nil, err
	}
	return toMapList(res, "list"), nil
}

func (t *ircTool) SpamfilterList(ctx context.Context) ([]map[string]any, error) {
	if t.irc == nil {
		return nil, errors.New("no IRC connection")
	}
	res, err := t.irc.Query(ctx, "spamfilter.list", nil)
	if err != nil {
		return nil, err
	}
	return toMapList(res, "list"), nil
}

func (t *ircTool) Stats(ctx context.Context) (map[string]any, error) {
	if t.irc == nil {
		return nil, errors.New("no IRC connection")
	}
	res, err := t.irc.Query(ctx, "stats.get", map[string]any{
		"object_detail_level": 2,
	})
	if err != nil {
		return nil, err
	}
	if m, ok := res.(map[string]any); ok {
		return m, nil
	}
	return nil, fmt.Errorf("unexpected stats.get result")
}

func toMapList(res any, key string) []map[string]any {
	if res == nil {
		return nil
	}
	if m, ok := res.(map[string]any); ok {
		if v, ok := m[key]; ok {
			if arr, ok := v.([]any); ok {
				out := make([]map[string]any, 0, len(arr))
				for _, e := range arr {
					if em, ok := e.(map[string]any); ok {
						out = append(out, em)
					}
				}
				return out
			}
		}
	}
	if arr, ok := res.([]any); ok {
		out := make([]map[string]any, 0, len(arr))
		for _, e := range arr {
			if em, ok := e.(map[string]any); ok {
				out = append(out, em)
			}
		}
		return out
	}
	return nil
}

func getString(m map[string]any, keys ...string) string {
	cur := any(m)
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	s, _ := cur.(string)
	return s
}

func getInt(m map[string]any, keys ...string) int64 {
	cur := any(m)
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0
		}
		cur = mm[k]
	}
	switch v := cur.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

func getBool(m map[string]any, keys ...string) bool {
	cur := any(m)
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur = mm[k]
	}
	b, _ := cur.(bool)
	return b
}

func getStringList(m map[string]any, keys ...string) []string {
	cur := any(m)
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	if arr, ok := cur.([]any); ok {
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

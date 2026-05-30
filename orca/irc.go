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

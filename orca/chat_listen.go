package orca

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unicode"

	"backend/ai"
	"backend/bot"
)

// chatListenEnabled gates passive channel-message addressing. Defaults
// on; flip to false with ORCA_CHAT_LISTEN=false if cost or noise becomes
// an issue (each addressed message costs a chat round-trip).
func chatListenEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ORCA_CHAT_LISTEN")))
	if v == "" {
		return true
	}
	return v != "0" && v != "false" && v != "no" && v != "off"
}

// chatToolBudget caps tool round-trips for a chat-addressed query.
// Same reasoning as voiceToolBudget: terse chat reply, low latency
// budget. Bump to 5+ if responses are getting truncated for tool-heavy
// asks like "audit who matches *@evil.example.com and ban them".
const chatToolBudget = 4

// addressMatcher decides whether a channel message is targeted at the
// bot. Rule (per user request, simpler and more reliable than regex
// gymnastics): after stripping all punctuation to spaces, the nick
// must be either the FIRST or SECOND word of the message. Anywhere
// else and we ignore -- avoids false positives like "did you see the
// movie about Orca" or "thanks orca", and forces deliberate addressing.
//
// Examples that MATCH:
//   "Orca" / "Orca?" / "Orca, what time?"     (1st word)
//   "Hey Orca, what?" / "@Orca explain" / "OK Orca do X"   (2nd word)
//
// Examples that DON'T match:
//   "did you see that movie about Orca"
//   "talk about Orca it wouldn't care?"
//   "are you there orca?"   (4th word -- ask "orca, are you there?" instead)
//   "I love orca whales"
type addressMatcher struct {
	nick      string
	nickLower string
}

func newAddressMatcher(nick string) *addressMatcher {
	return &addressMatcher{
		nick:      nick,
		nickLower: strings.ToLower(nick),
	}
}

// match returns (addressed, query). If addressed=false, the message
// isn't for us. Query is the residual text after the addressing
// prefix is stripped; empty query means a bare ping like "Orca?".
func (m *addressMatcher) match(text string) (bool, string) {
	if m.nick == "" {
		return false, ""
	}
	t := strings.TrimSpace(text)
	if t == "" {
		return false, ""
	}

	tokens := tokenizeStrippingPunct(t)
	if len(tokens) == 0 {
		return false, ""
	}

	idx := -1
	if strings.ToLower(tokens[0]) == m.nickLower {
		idx = 0
	} else if len(tokens) > 1 && strings.ToLower(tokens[1]) == m.nickLower {
		idx = 1
	}
	if idx == -1 {
		return false, ""
	}

	rest := strings.TrimSpace(strings.Join(tokens[idx+1:], " "))
	if rest == "" {
		// e.g. just "Orca?" or "Hey Orca" -- treat as a ping.
		return true, "(Acknowledge briefly that you're here.)"
	}
	return true, rest
}

// tokenizeStrippingPunct turns the message into whitespace-separated
// tokens with every non-letter/non-digit character treated as a word
// separator. So "Hey, Orca!" -> ["Hey", "Orca"], "@orca foo" -> ["orca",
// "foo"], "isn't" -> ["isn", "t"] (good enough -- we only look at the
// first two tokens).
func tokenizeStrippingPunct(s string) []string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune(' ')
		}
	}
	return strings.Fields(b.String())
}

// handleChannelMessage is the dispatch entry from OnEvent. Filters out
// the cases we don't care about (TAGMSG, NOTICE, own messages,
// addressed-to-someone-else), then runs the same tool-enabled chat
// loop the voice path uses and posts the answer via gw.SendMessage.
func (o *Orca) handleChannelMessage(ctx context.Context, m bot.MessageCreate) {
	if !chatListenEnabled() {
		return
	}
	if m.IsNotice || m.IsTagmsg {
		return // never auto-reply to NOTICEs (loops!) or TAGMSGs
	}
	if m.Content == "" {
		return
	}

	channel, _ := m.Channel["name"].(string)
	speaker, _ := m.Author["nick"].(string)
	if channel == "" || speaker == "" {
		return
	}
	// Never reply to ourselves.
	if strings.EqualFold(speaker, o.nick) {
		return
	}
	// Don't double-handle slash-command invocations: those already
	// have a dedicated path through bot.Invocation. "!ask query" /
	// "/ask query" should go through that, not the chat-listen loop.
	if t := strings.TrimSpace(m.Content); strings.HasPrefix(t, "!") || strings.HasPrefix(t, "/") {
		return
	}

	matched, query := o.addressMatcher().match(m.Content)
	if !matched {
		return
	}
	if query == "" {
		return
	}

	go o.runChatReply(ctx, channel, speaker, query)
}

// addressMatcher lazily builds the matcher once and caches it. Nick
// can't change during a single bot session, so this is fine.
func (o *Orca) addressMatcher() *addressMatcher {
	o.addrMu.Lock()
	defer o.addrMu.Unlock()
	if o.addrMatcher == nil {
		o.addrMatcher = newAddressMatcher(o.nick)
	}
	return o.addrMatcher
}

// runChatReply is the per-message worker: same tool-loop shape as
// askPlain but tuned for chat (text output, longer context budget, no
// TTS). Posts the reply with SendMessage.
func (o *Orca) runChatReply(ctx context.Context, channel, speaker, query string) {
	gw := o.Gateway()
	if gw == nil {
		log.Printf("[orca/chat] %s/%s: no gateway, can't reply", channel, speaker)
		return
	}
	if o.chat == nil {
		return
	}

	key := ConvKey{Channel: channel}
	conv := o.memory.GetOrCreate(key)

	speakerNote := ""
	if conv.LastSpeaker != "" && conv.LastSpeaker != speaker {
		speakerNote = fmt.Sprintf("The current speaker changed: now talking to %s (previously %s).",
			speaker, conv.LastSpeaker)
	}

	sysPrompt := o.chatSystemPrompt(channel, speaker, conv)
	now := time.Now().UTC()
	conv.append(ConvTurn{
		Role: ai.RoleUser, Nick: speaker, Time: now, Content: query,
	})
	o.logger.AppendTurn(key, ConvTurn{
		Role: ai.RoleUser, Nick: speaker, Time: now, Content: query,
	})

	messages := o.memory.BuildMessages(conv, sysPrompt, speakerNote, "")
	tools := o.aiTools()

	var answer string
	for iter := 0; iter < chatToolBudget; iter++ {
		resp, err := o.chat.Chat(ctx, ai.ChatRequest{
			Messages: messages,
			Tools:    tools,
		})
		if err != nil {
			log.Printf("[orca/chat] %s/%s: ask: %v", channel, speaker, err)
			return
		}
		asstTurn := ConvTurn{
			Role:      ai.RoleAssistant,
			Time:      time.Now().UTC(),
			Content:   resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		}
		conv.append(asstTurn)
		o.logger.AppendTurn(key, asstTurn)

		if len(resp.Message.ToolCalls) == 0 {
			answer = strings.TrimSpace(resp.Message.Content)
			break
		}
		messages = append(messages, ai.Message{
			Role: ai.RoleAssistant, Content: resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		})
		for _, tc := range resp.Message.ToolCalls {
			params := map[string]any{}
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &params)
			}
			result, terr := o.invokeAITool(ctx, tc.Function.Name, params, nil)
			if terr != nil {
				result = fmt.Sprintf(`{"error":%q}`, terr.Error())
			}
			toolTurn := ConvTurn{
				Role: ai.RoleTool, Time: time.Now().UTC(),
				Content: result, ToolName: tc.Function.Name, ToolCall: tc,
			}
			conv.append(toolTurn)
			o.logger.AppendTurn(key, toolTurn)
			messages = append(messages, ai.Message{
				Role: ai.RoleTool, Content: result,
				Name: tc.Function.Name, ToolCallID: tc.ID,
			})
		}
	}

	if answer == "" {
		return
	}
	// Quote the speaker so the channel can tell who Orca's answering.
	out := fmt.Sprintf("%s: %s", speaker, answer)
	if err := gw.SendMessage(channel, out, false); err != nil {
		log.Printf("[orca/chat] %s: SendMessage: %v", channel, err)
	}

	go o.memory.MaybeCompact(context.Background(), conv)
}

func (o *Orca) chatSystemPrompt(channel, speaker string, conv *Conversation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are Orca, an IRC ops assistant active in channel %s. ", channel)
	fmt.Fprintf(&b, "A user addressed you directly in chat (not via /ask). ")
	fmt.Fprintf(&b, "Reply concisely -- one or two short sentences usually, more only if the question demands detail. No Markdown headers, no code fences unless quoting actual code/output. ")
	fmt.Fprintf(&b, "The speaker is %s. Use the available admin tools when the question needs real server data; don't guess.\n", speaker)
	if conv.LastSpeaker != "" && conv.LastSpeaker != speaker {
		fmt.Fprintf(&b, "Previous speaker was %s.\n", conv.LastSpeaker)
	}
	return b.String()
}


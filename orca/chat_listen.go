package orca

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

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
// bot, and if so what the residual query is.
//
// Match rules (case-insensitive, all checked):
//
//   1. Starts with optional polite prefix + nick: "hey orca, ..." /
//      "okay orca - ..." / "orca: ..." / "@orca ..."
//   2. @nick mention anywhere: "could you @orca explain this" -> "could
//      you explain this"
//   3. Bare nick mention with a question elsewhere: "is orca around?"
//      -> the whole sentence becomes the query
//
// Designed to be permissive about punctuation (Whisper-style commas
// /periods between words) and language-agnostic where the bot's nick
// is the anchor token. For free-form polite prefixes ("could you
// please"), we don't care because rule (1) doesn't require them.
type addressMatcher struct {
	nick string
	// startRe matches a leading polite-prefix + nick + delimiter.
	// Capture group 1 is everything after.
	startRe *regexp.Regexp
	// inlineRe matches an @-mention anywhere in the message.
	inlineRe *regexp.Regexp
	// bareRe matches the nick anywhere as a standalone token.
	bareRe *regexp.Regexp
}

func newAddressMatcher(nick string) *addressMatcher {
	if nick == "" {
		return &addressMatcher{nick: nick}
	}
	// Quote so regex specials in nick (unlikely but possible) don't
	// blow up. Word-boundary works fine for letter/digit nicks.
	q := regexp.QuoteMeta(nick)
	return &addressMatcher{
		nick:     nick,
		// Match: optional @, optional polite prefix word, the bot nick, then
		// either end-of-string (bare ping) or a delimiter run + the rest.
		// The (?:...)? around the trailing piece is what lets "Hey Orca"
		// and bare "Orca" match without requiring trailing punctuation.
		startRe:  regexp.MustCompile(`(?i)^[\s@]*(?:hey|hi|hello|ok|okay|yo|hej|salut|hola|ciao|oi|olá|привет|hai|あの|ねえ|なあ|嗨|喂|你好)?[\s,]*@?` + q + `\b(?:[\s,.:;!?\-—–]+(.*))?$`),
		inlineRe: regexp.MustCompile(`(?i)\B@` + q + `\b[\s,.:;!?\-—–]*`),
		bareRe:   regexp.MustCompile(`(?i)\b` + q + `\b`),
	}
}

// match returns (addressed, query). If addressed=false, the message
// isn't for us. Query is the text to feed to the LLM with the bot's
// own name stripped where possible.
func (m *addressMatcher) match(text string) (bool, string) {
	if m.nick == "" || m.startRe == nil {
		return false, ""
	}
	t := strings.TrimSpace(text)
	if t == "" {
		return false, ""
	}

	// 1. Leading address.
	if sub := m.startRe.FindStringSubmatch(t); sub != nil {
		rest := strings.TrimSpace(sub[1])
		if rest == "" {
			// e.g. just "Orca?" or "hey orca!" -- treat as a ping.
			return true, "(Acknowledge briefly that you're here.)"
		}
		return true, rest
	}

	// 2. Inline @mention -- strip it and run the rest.
	if m.inlineRe.MatchString(t) {
		cleaned := strings.TrimSpace(m.inlineRe.ReplaceAllString(t, " "))
		if cleaned == "" {
			return true, "(Acknowledge briefly that you're here.)"
		}
		return true, cleaned
	}

	// 3. Bare nick mention + question mark anywhere -> probably a
	//    question addressed to us. Conservative: also require the
	//    message to end with "?" so "I saw orca yesterday" doesn't
	//    trigger.
	if strings.HasSuffix(t, "?") && m.bareRe.MatchString(t) {
		return true, t
	}

	return false, ""
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


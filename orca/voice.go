package orca

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"backend/ai"
)

// VoiceConfig captures the env-driven setup for Orca's voice subsystem.
type VoiceConfig struct {
	Channels      []string      // ORCA_VOICE_CHANNELS
	WakeOnly      bool          // ORCA_VOICE_WAKE_ONLY=true to require a wake word every turn
	UtteranceMax  time.Duration // safety cap on a single utterance
	MirrorChannel string        // text channel for transcript mirror (auto from ORCA_CHANNELS)
}

func loadVoiceConfig(o *Orca) VoiceConfig {
	return VoiceConfig{
		Channels:      splitCSV(os.Getenv("ORCA_VOICE_CHANNELS")),
		WakeOnly:      strings.EqualFold(os.Getenv("ORCA_VOICE_WAKE_ONLY"), "true"),
		UtteranceMax:  30 * time.Second,
		MirrorChannel: o.pickVoiceMirrorChannel(),
	}
}

// voiceSubsystem owns the audio loop for one Orca instance across all
// configured voice channels.
type voiceSubsystem struct {
	o      *Orca
	cfg    VoiceConfig
	tap    VoiceTap
	wake   *wakeMatcher
	stt    ai.STTProvider
	tts    ai.TTSProvider
	chat   ai.ChatProvider

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

// WithVoiceTap replaces Orca's voice audio backend. Call before Start.
// Without a real tap, the audio path is a no-op (logs only).
func (o *Orca) WithVoiceTap(t VoiceTap) {
	if t == nil {
		return
	}
	o.voiceTap = t
}

// startVoice spins up the listen loops for every configured voice channel.
// Returns immediately; loops run until ctx is cancelled.
func (o *Orca) startVoice(ctx context.Context) {
	o.voiceChannels = splitCSV(os.Getenv("ORCA_VOICE_CHANNELS"))
	if !o.hasVoiceChannels() {
		return
	}
	if o.voiceTap == nil {
		o.voiceTap = nopVoiceTap{}
	}

	cfg := loadVoiceConfig(o)
	vs := &voiceSubsystem{
		o:       o,
		cfg:     cfg,
		tap:     o.voiceTap,
		wake:    newWakeMatcher(),
		stt:     o.stt,
		tts:     o.tts,
		chat:    o.chat,
		running: map[string]context.CancelFunc{},
	}
	o.voice = vs

	for _, ch := range cfg.Channels {
		ch := ch
		chCtx, cancel := context.WithCancel(ctx)
		vs.mu.Lock()
		vs.running[ch] = cancel
		vs.mu.Unlock()
		go vs.runChannel(chCtx, ch)
	}
}

func (vs *voiceSubsystem) runChannel(ctx context.Context, channel string) {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := vs.tap.Join(ctx, channel); err != nil {
			log.Printf("[orca/voice] %s: join: %v (retrying in %s)", channel, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second

		frames, err := vs.tap.Frames(ctx, channel)
		if err != nil {
			log.Printf("[orca/voice] %s: frames: %v", channel, err)
			_ = vs.tap.Leave(ctx, channel)
			continue
		}

		log.Printf("[orca/voice] %s: listening (wake_only=%v)", channel, vs.cfg.WakeOnly)
		vs.consume(ctx, channel, frames)
		_ = vs.tap.Leave(ctx, channel)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (vs *voiceSubsystem) consume(ctx context.Context, channel string, frames <-chan AudioFrame) {
	type utterance struct {
		speaker    string
		pcm        bytes.Buffer
		sampleRate int
		channels   int
		started    time.Time
	}
	active := map[string]*utterance{}

	flush := func(u *utterance) {
		if u == nil || u.pcm.Len() == 0 {
			return
		}
		go vs.handleUtterance(ctx, channel, u.speaker,
			wavWrap(u.pcm.Bytes(), u.sampleRate, u.channels))
	}

	for {
		select {
		case <-ctx.Done():
			return
		case f, ok := <-frames:
			if !ok {
				return
			}
			u := active[f.Speaker]
			if u == nil {
				u = &utterance{
					speaker:    f.Speaker,
					sampleRate: f.SampleRate,
					channels:   f.Channels,
					started:    time.Now(),
				}
				active[f.Speaker] = u
			}
			u.pcm.Write(f.PCM)
			if f.EndOfUtterance || time.Since(u.started) > vs.cfg.UtteranceMax {
				flush(u)
				delete(active, f.Speaker)
			}
		}
	}
}

func (vs *voiceSubsystem) handleUtterance(ctx context.Context, channel, speaker string, wav []byte) {
	if vs.stt == nil {
		return
	}
	resp, err := vs.stt.STT(ctx, ai.STTRequest{
		Audio:    wav,
		MimeType: "audio/wav",
	})
	if err != nil {
		log.Printf("[orca/voice] %s/%s: stt: %v", channel, speaker, err)
		return
	}
	transcript := strings.TrimSpace(resp.Text)
	if transcript == "" {
		return
	}

	// Mirror the transcript into the voice channel itself as a PRIVMSG
	// from Orca's ghost ("<speaker> their utterance"), so the text-side
	// users see what was said in the call. Voice channels (^) accept
	// PRIVMSGs, and the bot's pushbot gateway exposes a SendMessage
	// op for spontaneous channel sends (no invocation context needed).
	log.Printf("[orca/voice] %s/%s: %q", channel, speaker, transcript)
	if gw := vs.o.Gateway(); gw != nil {
		mirrorMsg := fmt.Sprintf("<%s> %s", speaker, transcript)
		if err := gw.SendMessage(channel, mirrorMsg, false); err != nil {
			log.Printf("[orca/voice] %s: mirror PRIVMSG: %v", channel, err)
		}
	}

	matched, query := vs.wake.match(transcript)
	if vs.cfg.WakeOnly && !matched {
		return
	}
	if !matched {
		query = transcript
	}
	if query == "" {
		return
	}

	answer, err := vs.askPlain(ctx, channel, speaker, query)
	if err != nil {
		log.Printf("[orca/voice] %s/%s: ask: %v", channel, speaker, err)
		return
	}
	if vs.tts == nil {
		log.Printf("[orca/voice] %s answer (no TTS): %s", channel, truncate(answer, 200))
		return
	}
	audio, mime, terr := vs.tts.TTS(ctx, ai.TTSRequest{Text: answer})
	if terr != nil {
		log.Printf("[orca/voice] %s: tts: %v", channel, terr)
		return
	}
	log.Printf("[orca/voice] %s: tts ok mime=%s bytes=%d head=%q",
		channel, mime, len(audio), truncate(string(audio), 64))
	if serr := vs.tap.Speak(ctx, channel, audio, mime); serr != nil {
		log.Printf("[orca/voice] %s: speak: %v", channel, serr)
	}
}

// voiceToolBudget caps how many tool round-trips a single spoken
// question can drive. Lower than /ask because voice round-trip latency
// is felt much more sharply -- 1-2 tool calls is usually plenty to
// resolve "who's in #X?" / "what channels exist?" style asks.
const voiceToolBudget = 3

// askPlain runs an /ask-shaped exchange with the same admin-tool access
// /ask has, but with a smaller iteration budget so voice latency stays
// reasonable. Memory is kept per voice channel via the same ConvKey,
// so a follow-up question in voice resolves the context of the previous one.
func (vs *voiceSubsystem) askPlain(ctx context.Context, channel, speaker, query string) (string, error) {
	if vs.chat == nil {
		return "", fmt.Errorf("no chat provider")
	}
	key := ConvKey{Channel: channel}
	conv := vs.o.memory.GetOrCreate(key)

	speakerChanged := conv.LastSpeaker != "" && conv.LastSpeaker != speaker
	speakerNote := ""
	if speakerChanged {
		speakerNote = fmt.Sprintf("The current speaker changed: now talking to %s (previously %s).",
			speaker, conv.LastSpeaker)
	}

	sysPrompt := vs.voiceSystemPrompt(channel, speaker, conv)
	conv.append(ConvTurn{
		Role:    ai.RoleUser,
		Nick:    speaker,
		Time:    time.Now().UTC(),
		Content: query,
	})
	vs.o.logger.AppendTurn(key, ConvTurn{
		Role:    ai.RoleUser,
		Nick:    speaker,
		Time:    time.Now().UTC(),
		Content: query,
	})

	messages := vs.o.memory.BuildMessages(conv, sysPrompt, speakerNote, "")
	tools := vs.o.aiTools()

	var answer string
	for iter := 0; iter < voiceToolBudget; iter++ {
		resp, err := vs.chat.Chat(ctx, ai.ChatRequest{
			Messages: messages,
			Tools:    tools,
		})
		if err != nil {
			return "", err
		}
		asstTurn := ConvTurn{
			Role:      ai.RoleAssistant,
			Time:      time.Now().UTC(),
			Content:   resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		}
		conv.append(asstTurn)
		vs.o.logger.AppendTurn(key, asstTurn)

		if len(resp.Message.ToolCalls) == 0 {
			answer = strings.TrimSpace(resp.Message.Content)
			break
		}

		messages = append(messages, ai.Message{
			Role:      ai.RoleAssistant,
			Content:   resp.Message.Content,
			ToolCalls: resp.Message.ToolCalls,
		})
		for _, tc := range resp.Message.ToolCalls {
			params := map[string]any{}
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &params)
			}
			// Voice path has no WorkflowEmitter; invokeAITool tolerates nil.
			result, terr := vs.o.invokeAITool(ctx, tc.Function.Name, params, nil)
			if terr != nil {
				result = fmt.Sprintf(`{"error":%q}`, terr.Error())
			}
			toolTurn := ConvTurn{
				Role:     ai.RoleTool,
				Time:     time.Now().UTC(),
				Content:  result,
				ToolName: tc.Function.Name,
				ToolCall: tc,
			}
			conv.append(toolTurn)
			vs.o.logger.AppendTurn(key, toolTurn)
			messages = append(messages, ai.Message{
				Role:       ai.RoleTool,
				Content:    result,
				Name:       tc.Function.Name,
				ToolCallID: tc.ID,
			})
		}
	}

	if answer == "" {
		answer = "(no answer)"
	}
	conv.append(ConvTurn{
		Role:    ai.RoleAssistant,
		Time:    time.Now().UTC(),
		Content: answer,
	})
	vs.o.logger.AppendTurn(key, ConvTurn{
		Role:    ai.RoleAssistant,
		Time:    time.Now().UTC(),
		Content: answer,
	})
	go vs.o.memory.MaybeCompact(context.Background(), conv)
	return answer, nil
}

func (vs *voiceSubsystem) voiceSystemPrompt(channel, speaker string, conv *Conversation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "You are Orca, an IRC ops assistant, speaking aloud over a voice channel (%s). ", channel)
	fmt.Fprintf(&b, "Reply in one or two short spoken sentences -- no Markdown, no bullets, no code fences. ")
	fmt.Fprintf(&b, "The current speaker is %s.\n", speaker)
	if conv.LastSpeaker != "" && conv.LastSpeaker != speaker {
		fmt.Fprintf(&b, "The previous speaker was %s; the speaker just changed.\n", conv.LastSpeaker)
	}
	return b.String()
}

// wavWrap puts a minimal WAVE header around 16-bit PCM. STT providers
// reliably accept WAV uploads without negotiating a codec.
func wavWrap(pcm []byte, sampleRate, channels int) []byte {
	if sampleRate == 0 {
		sampleRate = 16000
	}
	if channels == 0 {
		channels = 1
	}
	byteRate := sampleRate * channels * 2
	blockAlign := channels * 2

	buf := bytes.NewBuffer(nil)
	buf.WriteString("RIFF")
	_ = binary.Write(buf, binary.LittleEndian, uint32(36+len(pcm)))
	buf.WriteString("WAVE")
	buf.WriteString("fmt ")
	_ = binary.Write(buf, binary.LittleEndian, uint32(16))
	_ = binary.Write(buf, binary.LittleEndian, uint16(1)) // PCM
	_ = binary.Write(buf, binary.LittleEndian, uint16(channels))
	_ = binary.Write(buf, binary.LittleEndian, uint32(sampleRate))
	_ = binary.Write(buf, binary.LittleEndian, uint32(byteRate))
	_ = binary.Write(buf, binary.LittleEndian, uint16(blockAlign))
	_ = binary.Write(buf, binary.LittleEndian, uint16(16))
	buf.WriteString("data")
	_ = binary.Write(buf, binary.LittleEndian, uint32(len(pcm)))
	buf.Write(pcm)
	return buf.Bytes()
}

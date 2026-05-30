package orca

import (
	"context"
	"log"
	"strings"
)

// VoiceTap is the boundary between Orca's voice orchestration and the
// audio media path. An implementation owns the actual WebRTC plumbing:
// joining the voice room, decoding peers' inbound audio into PCM frames,
// and writing Orca's TTS output back so other participants hear it.
//
// One Tap instance is shared across all configured voice channels; the
// channel name parameter identifies which room each call refers to.
type VoiceTap interface {
	// Join enters the SFU room for `channel`. Idempotent.
	Join(ctx context.Context, channel string) error

	// Leave exits the SFU room.
	Leave(ctx context.Context, channel string) error

	// Frames returns a channel that yields decoded PCM audio frames as
	// other participants speak. Implementations SHOULD perform their
	// own VAD/utterance segmentation and set EndOfUtterance to mark
	// boundaries so Orca can hand whole utterances to STT.
	Frames(ctx context.Context, channel string) (<-chan AudioFrame, error)

	// Speak plays an audio clip (mime per `mime`, raw bytes) into the
	// voice room as Orca. Implementations resample/encode as needed.
	Speak(ctx context.Context, channel string, audio []byte, mime string) error
}

// AudioFrame is one chunk of decoded PCM audio from a peer.
type AudioFrame struct {
	Channel        string
	Speaker        string
	PCM            []byte
	SampleRate     int
	Channels       int
	EndOfUtterance bool
}

// nopVoiceTap is the default tap that logs operations and emits no audio.
// Replace via WithVoiceTap to plug in the real SFU-backed implementation.
type nopVoiceTap struct{}

func (nopVoiceTap) Join(ctx context.Context, channel string) error {
	log.Printf("[orca/voice] join %s (no tap installed -- audio path is a no-op)", channel)
	return nil
}

func (nopVoiceTap) Leave(ctx context.Context, channel string) error {
	log.Printf("[orca/voice] leave %s", channel)
	return nil
}

func (nopVoiceTap) Frames(ctx context.Context, channel string) (<-chan AudioFrame, error) {
	ch := make(chan AudioFrame)
	go func() {
		<-ctx.Done()
		close(ch)
	}()
	return ch, nil
}

func (nopVoiceTap) Speak(ctx context.Context, channel string, audio []byte, mime string) error {
	if len(audio) == 0 {
		return nil
	}
	log.Printf("[orca/voice] speak %d bytes (%s) into %s (no tap installed)",
		len(audio), mime, channel)
	return nil
}

// hasVoiceChannels returns the configured ^voice channels for Orca.
func (o *Orca) hasVoiceChannels() bool {
	return len(o.voiceChannels) > 0
}

// pickVoiceMirrorChannel returns the text channel transcripts go to,
// or "" if no text channel is configured to mirror into.
func (o *Orca) pickVoiceMirrorChannel() string {
	for _, c := range o.channels {
		if strings.HasPrefix(c, "#") || strings.HasPrefix(c, "&") {
			return c
		}
	}
	return ""
}

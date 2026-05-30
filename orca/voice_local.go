package orca

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// LocalParticipantAPI is the subset of the main package's voiceManager
// that we depend on. Keeping a mirror interface here lets the orca
// subpackage stay free of main-package imports; main passes a small
// adapter that satisfies it.
type LocalParticipantAPI interface {
	RegisterLocal(nick, channel string, onRTP LocalRTPCallback) (LocalPeer, error)
}

type LocalRTPCallback func(speaker, kind string, payload []byte)

type LocalPeer interface {
	SendOpus(rtpPacket []byte) error
	Stop() error
}

// localTap is a VoiceTap backed by the in-process SFU LocalParticipant.
// Audio I/O is wired but the data is raw RTP packets — Opus codec
// encode/decode lives outside this layer and is the next milestone.
type localTap struct {
	api  LocalParticipantAPI
	nick string

	mu     sync.Mutex
	peers  map[string]LocalPeer        // channel -> registered local peer
	frames map[string]chan AudioFrame  // channel -> outbound to Orca's loop
}

func NewLocalTap(api LocalParticipantAPI, nick string) VoiceTap {
	return &localTap{
		api:    api,
		nick:   nick,
		peers:  map[string]LocalPeer{},
		frames: map[string]chan AudioFrame{},
	}
}

func (t *localTap) Join(ctx context.Context, channel string) error {
	if t.api == nil {
		return fmt.Errorf("no LocalParticipantAPI")
	}
	t.mu.Lock()
	if _, ok := t.peers[channel]; ok {
		t.mu.Unlock()
		return nil
	}
	ch := make(chan AudioFrame, 256)
	t.frames[channel] = ch
	t.mu.Unlock()

	cb := func(speaker, kind string, payload []byte) {
		if kind != "audio" {
			return
		}
		// Non-blocking publish into Orca's frame channel; drop on
		// backpressure so an idle voice consumer can't stall the SFU's
		// fan-out goroutine.
		select {
		case ch <- AudioFrame{
			Channel: channel,
			Speaker: speaker,
			PCM:     payload, // raw Opus RTP for now; decoded by a later codec layer
		}:
		default:
		}
	}
	peer, err := t.api.RegisterLocal(t.nick, channel, cb)
	if err != nil {
		t.mu.Lock()
		delete(t.frames, channel)
		t.mu.Unlock()
		return err
	}
	t.mu.Lock()
	t.peers[channel] = peer
	t.mu.Unlock()
	log.Printf("[orca/voice] local peer registered in %s", channel)
	return nil
}

func (t *localTap) Leave(ctx context.Context, channel string) error {
	t.mu.Lock()
	peer := t.peers[channel]
	delete(t.peers, channel)
	if ch, ok := t.frames[channel]; ok {
		close(ch)
		delete(t.frames, channel)
	}
	t.mu.Unlock()
	if peer != nil {
		return peer.Stop()
	}
	return nil
}

func (t *localTap) Frames(ctx context.Context, channel string) (<-chan AudioFrame, error) {
	t.mu.Lock()
	ch, ok := t.frames[channel]
	t.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("not joined to %s", channel)
	}
	return ch, nil
}

func (t *localTap) Speak(ctx context.Context, channel string, audio []byte, mime string) error {
	t.mu.Lock()
	peer := t.peers[channel]
	t.mu.Unlock()
	if peer == nil {
		return fmt.Errorf("not joined to %s", channel)
	}
	// TODO codec layer: incoming bytes are typically MP3/OGG from a TTS
	// provider; need MP3-decode -> PCM -> Opus-encode -> RTP-frame and
	// write each Opus RTP packet via peer.SendOpus.  For now log only.
	log.Printf("[orca/voice] speak %d bytes (%s) in %s — codec not yet wired",
		len(audio), mime, channel)
	return nil
}

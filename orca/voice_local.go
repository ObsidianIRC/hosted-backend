package orca

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
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

	demux := newSpeakerDemux(channel, ch)
	cb := func(speaker, kind string, payload []byte) {
		if kind != "audio" {
			return
		}
		demux.feed(speaker, payload)
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
	return speakOpus(peer, audio)
}

// silenceRMS is the squared-amplitude threshold that marks a frame as
// silence. ~30 dB below full-scale; works for typical voice levels.
const (
	silenceRMS         = 1.0e5
	silenceFramesEnd   = 25 // 25 * 20 ms = 500 ms of silence ends an utterance
	maxUtteranceFrames = 1500 // hard cap ~30 s
)

// speakerDemux maintains one decoder + utterance buffer per inbound
// speaker SSRC so frames from different speakers in the same channel
// don't get interleaved.
type speakerDemux struct {
	channel string
	out     chan AudioFrame

	mu      sync.Mutex
	streams map[uint32]*speakerStream
}

type speakerStream struct {
	speaker     string
	dec         *OpusDecoder
	pcm         []int16
	silentCount int
	frames      int
	lastSeen    time.Time
}

func newSpeakerDemux(channel string, out chan AudioFrame) *speakerDemux {
	return &speakerDemux{
		channel: channel,
		out:     out,
		streams: map[uint32]*speakerStream{},
	}
}

func (d *speakerDemux) feed(speaker string, rtpPacket []byte) {
	payload, ssrc, err := DepacketizeOpus(rtpPacket)
	if err != nil || len(payload) == 0 {
		return
	}
	d.mu.Lock()
	st, ok := d.streams[ssrc]
	if !ok {
		dec, derr := NewOpusDecoder()
		if derr != nil {
			d.mu.Unlock()
			return
		}
		st = &speakerStream{speaker: speaker, dec: dec}
		d.streams[ssrc] = st
	}
	st.speaker = speaker
	st.lastSeen = time.Now()
	d.mu.Unlock()

	pcm, err := st.dec.Decode(payload)
	if err != nil {
		return
	}
	st.pcm = append(st.pcm, pcm...)
	st.frames++

	if PCMRMS(pcm) < silenceRMS {
		st.silentCount++
	} else {
		st.silentCount = 0
	}

	if st.silentCount >= silenceFramesEnd || st.frames >= maxUtteranceFrames {
		d.flush(ssrc, true)
	}
}

func (d *speakerDemux) flush(ssrc uint32, endOfUtterance bool) {
	d.mu.Lock()
	st := d.streams[ssrc]
	if st == nil || len(st.pcm) == 0 {
		d.mu.Unlock()
		return
	}
	pcm := st.pcm
	speaker := st.speaker
	st.pcm = nil
	st.frames = 0
	st.silentCount = 0
	d.mu.Unlock()

	// STT prefers mono 16 kHz; downconvert here so wavWrap doesn't have
	// to know the source rate. Stereo->mono first, then 48k->16k.
	mono := StereoToMono(pcm)
	mono = Resample(mono, opusSampleRate, 16000, 1)
	pcmBytes := int16ToBytes(mono)

	frame := AudioFrame{
		Channel:        d.channel,
		Speaker:        speaker,
		PCM:            pcmBytes,
		SampleRate:     16000,
		Channels:       1,
		EndOfUtterance: endOfUtterance,
	}
	select {
	case d.out <- frame:
	default:
		// Backpressure: drop the utterance rather than stalling the
		// SFU fan-out goroutine.
	}
}

func int16ToBytes(samples []int16) []byte {
	out := make([]byte, len(samples)*2)
	for i, s := range samples {
		out[2*i] = byte(s)
		out[2*i+1] = byte(s >> 8)
	}
	return out
}

// speakOpus is the outbound path: MP3/WAV bytes from the TTS provider
// get decoded to PCM, resampled to 48 kHz stereo, encoded to Opus in
// 20 ms frames, RTP-wrapped, and written to the LocalPeer's outbound
// track at real-time pacing.
func speakOpus(peer LocalPeer, audio []byte) error {
	pcm, srcRate, err := DecodeMP3(audio)
	if err != nil {
		return fmt.Errorf("mp3 decode: %w", err)
	}
	// go-mp3 yields 16-bit stereo PCM. Resample if the rate isn't
	// already Opus's 48 kHz expectation.
	if srcRate != opusSampleRate {
		pcm = Resample(pcm, srcRate, opusSampleRate, 2)
	}

	enc, err := NewOpusEncoder()
	if err != nil {
		return fmt.Errorf("opus encoder: %w", err)
	}
	pktr := NewRTPPacketizer(NextSSRC())

	frameSize := opusSamplesFrame * opusChannels // 1920 samples per 20 ms
	frameInterval := time.Duration(opusFrameMs) * time.Millisecond

	deadline := time.Now()
	for off := 0; off < len(pcm); off += frameSize {
		end := off + frameSize
		if end > len(pcm) {
			// Pad the trailing partial frame with zeros so the encoder
			// gets a full frame and we don't truncate the tail.
			padded := make([]int16, frameSize)
			copy(padded, pcm[off:])
			payload, eerr := enc.EncodeFrame(padded)
			if eerr != nil {
				return fmt.Errorf("opus encode: %w", eerr)
			}
			rtpBytes, werr := pktr.Wrap(payload)
			if werr != nil {
				return werr
			}
			if serr := peer.SendOpus(rtpBytes); serr != nil {
				return serr
			}
			break
		}
		payload, eerr := enc.EncodeFrame(pcm[off:end])
		if eerr != nil {
			return fmt.Errorf("opus encode: %w", eerr)
		}
		rtpBytes, werr := pktr.Wrap(payload)
		if werr != nil {
			return werr
		}
		if serr := peer.SendOpus(rtpBytes); serr != nil {
			return serr
		}
		// Real-time pacing: keep TTS playback at 1x speed instead of
		// flooding the SFU with a burst.
		deadline = deadline.Add(frameInterval)
		if d := time.Until(deadline); d > 0 {
			time.Sleep(d)
		} else {
			// Slipped a frame; reset the deadline to now so we don't
			// chase an ever-widening backlog if the encoder stalls.
			deadline = time.Now()
		}
	}
	return nil
}

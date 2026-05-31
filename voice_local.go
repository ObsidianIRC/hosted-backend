package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

// LocalParticipantAPI is what the orca subpackage (and any future
// in-process consumer) uses to attach to a voice room without going
// through WebRTC signaling. The SFU treats local participants as virtual
// peers: they receive other peers' RTP packets via callback and may
// publish their own RTP packets that get fanned out to remote peers.
type LocalParticipantAPI interface {
	RegisterLocal(nick, channel string, onRTP RTPCallback) (LocalPeer, error)
}

// RTPCallback is invoked once per RTP packet that arrives in the room
// from any non-local peer. `speaker` is the publishing nick, `kind` is
// "audio" or "video", `payload` is the raw RTP packet (not decoded).
// The callback runs on the publisher's fan-out goroutine — it should
// not block.
type RTPCallback func(speaker, kind string, payload []byte)

// LocalPeer is the handle returned to an in-process participant. The
// orca framework keeps one per voice channel it participates in.
type LocalPeer interface {
	// SendOpus appends an Opus-encoded RTP packet to this peer's
	// outbound audio track. The track is created on first call and
	// subscribed to by every existing remote peer; subsequent calls
	// just write to it.
	SendOpus(rtpPacket []byte) error
	// SendVideoRTP appends a VP8 RTP packet to this peer's outbound
	// video track. The track is created up-front at RegisterLocal
	// (same lifecycle as audio) so first-packet renegotiation
	// latency doesn't chop the start of the playback.
	SendVideoRTP(rtpPacket []byte) error
	Stop() error
	// BroadcastSpeaking / BroadcastSilent emit presence updates so
	// remote clients' speaker activity indicators light up while
	// this local peer is producing audio. The methods are nil-safe;
	// callers can wrap with `defer peer.BroadcastSilent()` etc.
	BroadcastSpeaking()
	BroadcastSilent()
}

type voiceLocalPeer struct {
	nick    string
	room    *voiceRoom
	mgr     *voiceManager
	onRTP   RTPCallback
	joinedAt time.Time

	mu       sync.Mutex
	audio    *webrtc.TrackLocalStaticRTP
	video    *webrtc.TrackLocalStaticRTP
	stopped  bool
}

// RegisterLocal registers a local in-process participant in `channel`.
// If a regular (PC-backed) voicePeer already exists for that nick (e.g.
// because the IRC JOIN landed first), it is dropped and replaced with
// the local peer. Idempotent: re-registering the same nick replaces.
func (m *voiceManager) RegisterLocal(nick, channel string, onRTP RTPCallback) (LocalPeer, error) {
	if nick == "" {
		return nil, errors.New("nick required")
	}
	if !strings.HasPrefix(channel, "^") && !strings.HasPrefix(channel, "$") {
		return nil, fmt.Errorf("not a voice/stream channel: %s", channel)
	}
	m.markLocalExpected(channel, nick)

	room := m.getOrCreateRoom(channel)

	room.mu.Lock()
	if existing, ok := room.peers[nick]; ok {
		existing.close()
		delete(room.peers, nick)
	}
	if room.localPeers == nil {
		room.localPeers = map[string]*voiceLocalPeer{}
	}
	if prev, ok := room.localPeers[nick]; ok {
		prev.stop()
	}
	// Create the outbound audio track up-front so any peer that joins
	// later picks it up in their initial SDP offer (no renegotiation),
	// and any peer already in the room renegotiates BEFORE real audio
	// arrives. Without this, the first ~200 ms of every TTS reply gets
	// chopped because SendOpus would lazily create+subscribe the track
	// at the same instant it writes the first packet.
	track, terr := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{
			MimeType:    webrtc.MimeTypeOpus,
			ClockRate:   48000,
			Channels:    2,
			SDPFmtpLine: "minptime=10;useinbandfec=1",
		},
		fmt.Sprintf("%s-audio-local", nick),
		nick,
	)
	if terr != nil {
		room.mu.Unlock()
		return nil, fmt.Errorf("local-audio track: %w", terr)
	}
	vtrack, verr := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
		},
		fmt.Sprintf("%s-video-local", nick),
		nick,
	)
	if verr != nil {
		room.mu.Unlock()
		return nil, fmt.Errorf("local-video track: %w", verr)
	}
	lp := &voiceLocalPeer{
		nick:     nick,
		room:     room,
		mgr:      m,
		onRTP:    onRTP,
		joinedAt: time.Now(),
		audio:    track,
		video:    vtrack,
	}
	room.localPeers[nick] = lp
	room.mu.Unlock()

	// Push the tracks to anyone already in the room (one-time renegotiate).
	lp.subscribeOthersToTrack(track)
	lp.subscribeOthersToTrack(vtrack)

	m.broadcast(channel, "", signalEnvelope{
		Type:    "presence",
		Member:  nick,
		State:   "joined",
		Channel: channel,
		Role:    "streamer",
	})
	// Local peers always have an open mic (they don't toggle mute);
	// without an explicit "mic on" presence the client UI shows
	// them as muted forever.
	m.broadcast(channel, "", signalEnvelope{
		Type:    "presence",
		Member:  nick,
		State:   "on",
		Kind:    "mic",
		Channel: channel,
	})

	log.Printf("voice/local: registered %s in %s", nick, channel)
	return lp, nil
}

// BroadcastMicOn emits a presence{Kind:"mic", State:"on"} for this
// local peer. Called both at registration and any time a new peer
// joins (since the initial broadcast at registration has no audience
// when the bot starts up before any humans).
func (lp *voiceLocalPeer) BroadcastMicOn() {
	if lp == nil || lp.mgr == nil || lp.room == nil {
		return
	}
	lp.mgr.broadcast(lp.room.name, "", signalEnvelope{
		Type:    "presence",
		Member:  lp.nick,
		State:   "on",
		Kind:    "mic",
		Channel: lp.room.name,
	})
}

// BroadcastSpeaking emits a presence{State:"speaking"} for this local
// peer; call when an outbound TTS reply starts streaming so remote
// clients' activity indicators light up. Pair with BroadcastSilent
// when the reply finishes. The client matches on State (not Kind)
// for speaking/silent -- see applyPresence in voice.ts.
func (lp *voiceLocalPeer) BroadcastSpeaking() {
	if lp == nil || lp.mgr == nil || lp.room == nil {
		return
	}
	lp.mgr.broadcast(lp.room.name, "", signalEnvelope{
		Type:    "presence",
		Member:  lp.nick,
		State:   "speaking",
		Channel: lp.room.name,
	})
}

func (lp *voiceLocalPeer) BroadcastSilent() {
	if lp == nil || lp.mgr == nil || lp.room == nil {
		return
	}
	lp.mgr.broadcast(lp.room.name, "", signalEnvelope{
		Type:    "presence",
		Member:  lp.nick,
		State:   "silent",
		Channel: lp.room.name,
	})
}

func (m *voiceManager) markLocalExpected(channel, nick string) {
	m.localMu.Lock()
	if m.localExpected == nil {
		m.localExpected = map[string]map[string]bool{}
	}
	if m.localExpected[channel] == nil {
		m.localExpected[channel] = map[string]bool{}
	}
	m.localExpected[channel][nick] = true
	m.localMu.Unlock()
}

func (m *voiceManager) isLocalExpected(channel, nick string) bool {
	m.localMu.RLock()
	defer m.localMu.RUnlock()
	set, ok := m.localExpected[channel]
	if !ok {
		return false
	}
	return set[nick]
}

func (m *voiceManager) clearLocalExpected(channel, nick string) {
	m.localMu.Lock()
	if set, ok := m.localExpected[channel]; ok {
		delete(set, nick)
		if len(set) == 0 {
			delete(m.localExpected, channel)
		}
	}
	m.localMu.Unlock()
}

func (lp *voiceLocalPeer) SendOpus(rtpPacket []byte) error {
	lp.mu.Lock()
	if lp.stopped {
		lp.mu.Unlock()
		return errors.New("local peer stopped")
	}
	track := lp.audio
	lp.mu.Unlock()
	if track == nil {
		return errors.New("local peer has no audio track")
	}
	_, err := track.Write(rtpPacket)
	return err
}

func (lp *voiceLocalPeer) SendVideoRTP(rtpPacket []byte) error {
	lp.mu.Lock()
	if lp.stopped {
		lp.mu.Unlock()
		return errors.New("local peer stopped")
	}
	track := lp.video
	lp.mu.Unlock()
	if track == nil {
		return errors.New("local peer has no video track")
	}
	_, err := track.Write(rtpPacket)
	return err
}

// subscribeOthersToTrack attaches the local peer's newly-created track
// to every existing remote peer's PC and triggers renegotiation. Mirrors
// the second half of voicePeer.fanOutTrack so the local peer's audio
// reaches every other participant the same way a regular peer's would.
func (lp *voiceLocalPeer) subscribeOthersToTrack(track *webrtc.TrackLocalStaticRTP) {
	lp.room.mu.RLock()
	others := make([]*voicePeer, 0, len(lp.room.peers))
	for _, other := range lp.room.peers {
		others = append(others, other)
	}
	lp.room.mu.RUnlock()

	localID := track.ID()
	for _, other := range others {
		s, err := other.pc.AddTrack(track)
		if err != nil {
			log.Printf("voice/local: AddTrack(%s) -> %s: %v",
				localID, other.nick, err)
			continue
		}
		other.mu.Lock()
		if other.subSenders == nil {
			other.subSenders = map[string]*webrtc.RTPSender{}
		}
		other.subSenders[localID] = s
		other.mu.Unlock()
		log.Printf("voice/local: AddTrack(%s) -> %s ok", localID, other.nick)
		if lp.mgr != nil {
			lp.mgr.renegotiateFor(other)
		}
	}
}

func (lp *voiceLocalPeer) Stop() error {
	lp.stop()
	return nil
}

func (lp *voiceLocalPeer) stop() {
	lp.mu.Lock()
	if lp.stopped {
		lp.mu.Unlock()
		return
	}
	lp.stopped = true
	lp.mu.Unlock()

	if lp.room != nil {
		lp.room.mu.Lock()
		delete(lp.room.localPeers, lp.nick)
		channel := lp.room.name
		lp.room.mu.Unlock()
		if lp.mgr != nil {
			lp.mgr.broadcast(channel, "", signalEnvelope{
				Type:    "presence",
				Member:  lp.nick,
				State:   "left",
				Channel: channel,
			})
			lp.mgr.clearLocalExpected(channel, lp.nick)
			lp.mgr.reapEmpty(channel)
		}
	}
	log.Printf("voice/local: %s stopped", lp.nick)
}

// notifyLocalPeers is called from voicePeer.fanOutTrack's RTP pump after
// the regular per-packet fan-out, to deliver a copy of each packet to
// every registered local participant in the same room. Safe to call with
// no local peers (no-op).
func (r *voiceRoom) notifyLocalPeers(speakerNick, kind string, payload []byte) {
	r.mu.RLock()
	lps := make([]*voiceLocalPeer, 0, len(r.localPeers))
	for _, lp := range r.localPeers {
		lps = append(lps, lp)
	}
	r.mu.RUnlock()
	if len(lps) == 0 {
		return
	}
	// Local participants get a copy so the caller is free to keep using
	// the publisher's buffer for the next RTP read.
	cp := make([]byte, len(payload))
	copy(cp, payload)
	for _, lp := range lps {
		if lp.onRTP != nil {
			lp.onRTP(speakerNick, kind, cp)
		}
	}
}

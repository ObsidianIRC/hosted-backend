// voice.go -- WebRTC SFU + embedded TURN + IRCd bridge for the
// "^channel" voice rooms.
//
// Architecture:
//
//   ObsidianIRC client               obbyircd                  hosted-backend (this file)
//   ─────────────────                ────────                  ──────────────
//   TAGMSG ^vc @+obsidianirc/rtc=…   →                         (received via bridge)
//                                    ↓ voice.c module
//                                    ──── unix WS bridge ────► VoiceBridge
//                                                              ├─ VoiceRooms (SFU)
//                                                              └─ TURN server
//   ◄──── TAGMSG :server.name @+obsidianirc/rtc=… (back through the same bridge)
//
// All heavy lifting (TURN credentials, SDP munging, RTP forwarding)
// lives here.  The IRCd module is just a thin TAGMSG <-> JSON bridge.

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/turn/v3"
	"github.com/pion/webrtc/v4"
)

/* =====================================================================
 * Config
 * ===================================================================== */

type VoiceConfig struct {
	// Public hostname / IP that clients reach the TURN server through.
	// Defaults to the request's Host header derived value at runtime;
	// can be forced via VOICE_PUBLIC_IP for deployments behind NAT.
	PublicIP string
	// UDP port for TURN.  3478 is the IANA-assigned TURN port.
	TurnPort int
	// HMAC secret used to derive time-limited TURN credentials per
	// authenticated user.  Required.
	TurnAuthSecret string
	// Unix-socket path for the IRCd <-> backend bridge.  Defaults to
	// /tmp/obbyirc-voice.sock; obbyircd's voice module reads the
	// same env var (VOICE_BRIDGE_SOCKET) to find us.
	BridgeSocket string
	// Hard cap on participants per voice room.  Above this, joins
	// fail with a "room_full" error.
	MaxRoomSize int
	// ICE/TURN realm for the embedded TURN server.
	Realm string
}

func loadVoiceConfig() VoiceConfig {
	cfg := VoiceConfig{
		PublicIP:       os.Getenv("VOICE_PUBLIC_IP"),
		BridgeSocket:   os.Getenv("VOICE_BRIDGE_SOCKET"),
		TurnAuthSecret: os.Getenv("VOICE_TURN_SECRET"),
		Realm:          os.Getenv("VOICE_TURN_REALM"),
		MaxRoomSize:    25,
	}
	if cfg.BridgeSocket == "" {
		cfg.BridgeSocket = "/tmp/obbyirc-voice.sock"
	}
	if cfg.Realm == "" {
		cfg.Realm = "obsidianirc"
	}
	cfg.TurnPort = 3478
	if v := os.Getenv("VOICE_TURN_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			cfg.TurnPort = p
		}
	}
	if v := os.Getenv("VOICE_MAX_ROOM"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			cfg.MaxRoomSize = p
		}
	}
	return cfg
}

/* =====================================================================
 * TURN credentials
 * ===================================================================== */

// TURN REST credentials per the long-lived-credentials draft:
// https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00
//
// username = "<expiry-unix>:<account>"
// password = base64(HMAC-SHA1(secret, username))
//
// The TURN server uses the same secret to validate the password,
// rejecting anything past the expiry.
type TurnCreds struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URLs     []string `json:"urls"`
	TTL      int64  `json:"ttl"`
}

func mintTurnCreds(cfg VoiceConfig, account string, ttl time.Duration) TurnCreds {
	expiry := time.Now().Add(ttl).Unix()
	username := fmt.Sprintf("%d:%s", expiry, account)
	mac := hmac.New(sha1.New, []byte(cfg.TurnAuthSecret))
	mac.Write([]byte(username))
	password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	host := cfg.PublicIP
	if host == "" {
		host = "127.0.0.1"
	}
	urls := []string{
		fmt.Sprintf("turn:%s:%d?transport=udp", host, cfg.TurnPort),
	}
	return TurnCreds{
		Username: username,
		Password: password,
		URLs:     urls,
		TTL:      int64(ttl.Seconds()),
	}
}

// turnAuthHandler is pion/turn's RelayAuthHandler signature.  We
// recompute the expected HMAC for the supplied username; if the
// embedded expiry is past or the HMAC doesn't match, return false.
func turnAuthHandler(cfg VoiceConfig) turn.AuthHandler {
	return func(username, _realm string, _addr net.Addr) ([]byte, bool) {
		// username = "<expiry>:<account>"
		colon := strings.IndexByte(username, ':')
		if colon < 0 {
			return nil, false
		}
		expStr := username[:colon]
		exp, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil || time.Now().Unix() > exp {
			return nil, false
		}
		mac := hmac.New(sha1.New, []byte(cfg.TurnAuthSecret))
		mac.Write([]byte(username))
		password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		// pion/turn expects the *long-term-credential key* which is
		// MD5(username:realm:password) per RFC 5389.  turn.GenerateAuthKey
		// computes that for us.
		return turn.GenerateAuthKey(username, cfg.Realm, password), true
	}
}

/* =====================================================================
 * TURN server lifecycle
 * ===================================================================== */

func startTurnServer(cfg VoiceConfig) (*turn.Server, error) {
	if cfg.TurnAuthSecret == "" {
		return nil, errors.New(
			"VOICE_TURN_SECRET must be set to enable TURN")
	}
	addr := fmt.Sprintf("0.0.0.0:%d", cfg.TurnPort)
	udpConn, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("turn: udp listen %s: %w", addr, err)
	}
	publicIP := cfg.PublicIP
	if publicIP == "" {
		publicIP = "127.0.0.1"
	}
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm:       cfg.Realm,
		AuthHandler: turnAuthHandler(cfg),
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpConn,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP(publicIP),
					Address:      "0.0.0.0",
				},
			},
		},
	})
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("turn: new server: %w", err)
	}
	log.Printf("voice: TURN server listening on %s (public %s, realm %q)",
		addr, publicIP, cfg.Realm)
	return srv, nil
}

/* =====================================================================
 * SFU: rooms + peers
 * ===================================================================== */

// signalEnvelope is the JSON shape carried inside the
// +obsidianirc/rtc message tag in both directions.
type signalEnvelope struct {
	Type string `json:"type"`

	// "join" / "leave"
	Channel string `json:"channel,omitempty"`

	// "offer" / "answer"
	SDP string `json:"sdp,omitempty"`

	// "ice"
	Candidate     string `json:"cand,omitempty"`
	SDPMid        string `json:"mid,omitempty"`
	SDPMLineIndex *uint16 `json:"mlineidx,omitempty"`

	// state broadcast: "mic" / "video" / "speaking" / "silent" /
	// "deaf" / "screen"
	State string `json:"state,omitempty"`

	// presence (server->everyone)
	Members []string `json:"members,omitempty"`
	Member  string   `json:"member,omitempty"`

	// turn credentials (server->one) -- sent in response to "join"
	TURN *TurnCreds `json:"turn,omitempty"`

	// human-readable error
	Error string `json:"error,omitempty"`
}

type voiceRoom struct {
	name  string
	peers map[string]*voicePeer // keyed by nick
	mu    sync.RWMutex
}

func (r *voiceRoom) snapshotMembers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.peers))
	for nick := range r.peers {
		out = append(out, nick)
	}
	return out
}

type voicePeer struct {
	nick     string
	room     *voiceRoom
	pc       *webrtc.PeerConnection
	mu       sync.Mutex
	// One *TrackLocalStaticRTP per published track.  Other peers
	// AddTrack() these to receive this peer's media.
	publishedAudio *webrtc.TrackLocalStaticRTP
	publishedVideo *webrtc.TrackLocalStaticRTP
	// Senders we've added to this peer's PC, keyed by other-peer-nick
	// + kind ("audio"/"video"); used to remove on leave.
	subSenders map[string]*webrtc.RTPSender
}

type voiceManager struct {
	cfg   VoiceConfig
	mu    sync.RWMutex
	rooms map[string]*voiceRoom
	// Outgoing message channel back to the IRCd bridge.  All
	// signalEnvelopes that need to land at a client funnel through
	// here so the bridge can serialize -> JSON-tag -> TAGMSG.
	outbound func(target, payload string) error
}

func newVoiceManager(cfg VoiceConfig) *voiceManager {
	return &voiceManager{
		cfg:   cfg,
		rooms: map[string]*voiceRoom{},
	}
}

// peerConnectionConfig builds the ICE config that gets sent to clients
// (they run their own PCs and need our TURN URL/creds).
func (m *voiceManager) peerConnectionConfig() webrtc.Configuration {
	host := m.cfg.PublicIP
	if host == "" {
		host = "127.0.0.1"
	}
	return webrtc.Configuration{
		ICEServers: []webrtc.ICEServer{
			{URLs: []string{"stun:stun.l.google.com:19302"}},
			{
				URLs: []string{fmt.Sprintf(
					"turn:%s:%d?transport=udp", host, m.cfg.TurnPort)},
			},
		},
	}
}

func (m *voiceManager) getOrCreateRoom(name string) *voiceRoom {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rooms[name]; ok {
		return r
	}
	r := &voiceRoom{name: name, peers: map[string]*voicePeer{}}
	m.rooms[name] = r
	return r
}

func (m *voiceManager) reapEmpty(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rooms[name]; ok && len(r.peers) == 0 {
		delete(m.rooms, name)
	}
}

// handleJoin allocates a peer, opens a PeerConnection on the server
// side, and replies with a "joined" envelope plus TURN creds.
func (m *voiceManager) handleJoin(nick, channel, account string) {
	if !strings.HasPrefix(channel, "^") {
		m.send(nick, signalEnvelope{Type: "error", Error: "not a voice channel"})
		return
	}
	room := m.getOrCreateRoom(channel)
	room.mu.Lock()
	if len(room.peers) >= m.cfg.MaxRoomSize {
		room.mu.Unlock()
		m.send(nick, signalEnvelope{Type: "error", Error: "room_full"})
		return
	}
	if _, dup := room.peers[nick]; dup {
		// Idempotent: re-issue a fresh PC if a stale one still exists.
		room.peers[nick].close()
	}
	pc, err := webrtc.NewPeerConnection(m.peerConnectionConfig())
	if err != nil {
		room.mu.Unlock()
		m.send(nick, signalEnvelope{
			Type: "error", Error: "pc_alloc: " + err.Error(),
		})
		return
	}
	peer := &voicePeer{
		nick:       nick,
		room:       room,
		pc:         pc,
		subSenders: map[string]*webrtc.RTPSender{},
	}
	room.peers[nick] = peer
	members := make([]string, 0, len(room.peers))
	for n := range room.peers {
		if n == nick {
			continue
		}
		members = append(members, n)
	}
	room.mu.Unlock()

	// Subscribe to existing peers' tracks (so this new peer hears
	// them once their PC negotiation completes).
	room.mu.RLock()
	for _, other := range room.peers {
		if other.nick == nick {
			continue
		}
		if err := peer.subscribeTo(other); err != nil {
			log.Printf("voice: subscribe %s -> %s: %v",
				nick, other.nick, err)
		}
	}
	room.mu.RUnlock()

	// Hook ICE candidate emission so we relay them back to the client.
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		j := c.ToJSON()
		idx := j.SDPMLineIndex
		m.send(nick, signalEnvelope{
			Type:          "ice",
			Candidate:     j.Candidate,
			SDPMid:        firstStr(j.SDPMid),
			SDPMLineIndex: idx,
		})
	})

	// When the client publishes (audio / video), latch onto the
	// inbound track and fan it out.
	pc.OnTrack(func(remote *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		go peer.fanOutTrack(remote)
	})

	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		if s == webrtc.PeerConnectionStateFailed ||
			s == webrtc.PeerConnectionStateClosed ||
			s == webrtc.PeerConnectionStateDisconnected {
			m.handleLeave(nick, channel)
		}
	})

	turn := mintTurnCreds(m.cfg, account, 6*time.Hour)
	m.send(nick, signalEnvelope{
		Type:    "joined",
		Channel: channel,
		Members: members,
		TURN:    &turn,
	})

	// Tell every other peer that someone joined (presence broadcast,
	// not media-bearing).
	m.broadcast(channel, nick, signalEnvelope{
		Type:    "presence",
		Member:  nick,
		State:   "joined",
		Channel: channel,
	})
}

// subscribeTo adds an RTPSender for each track `other` is publishing
// to *this* peer's PeerConnection, so this peer receives `other`'s
// media.  Caller holds room.mu.RLock OR is in a path where
// concurrent modification of `other.publishedX` is impossible.
func (p *voicePeer) subscribeTo(other *voicePeer) error {
	other.mu.Lock()
	defer other.mu.Unlock()
	if other.publishedAudio != nil {
		s, err := p.pc.AddTrack(other.publishedAudio)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.subSenders[other.nick+"|audio"] = s
		p.mu.Unlock()
	}
	if other.publishedVideo != nil {
		s, err := p.pc.AddTrack(other.publishedVideo)
		if err != nil {
			return err
		}
		p.mu.Lock()
		p.subSenders[other.nick+"|video"] = s
		p.mu.Unlock()
	}
	return nil
}

// fanOutTrack reads RTP packets off the inbound track and writes them
// into the local fan-out track so all other peers' senders receive
// them.  The local fan-out track is created lazily on first packet.
func (p *voicePeer) fanOutTrack(remote *webrtc.TrackRemote) {
	kind := remote.Kind().String()
	codec := remote.Codec()
	local, err := webrtc.NewTrackLocalStaticRTP(
		codec.RTPCodecCapability,
		fmt.Sprintf("%s-%s", p.nick, kind),
		p.nick,
	)
	if err != nil {
		log.Printf("voice: fanout new track %s: %v", kind, err)
		return
	}
	p.mu.Lock()
	if kind == "audio" {
		p.publishedAudio = local
	} else if kind == "video" {
		p.publishedVideo = local
	}
	p.mu.Unlock()

	// Subscribe each existing peer to this new track.
	p.room.mu.RLock()
	for _, other := range p.room.peers {
		if other.nick == p.nick {
			continue
		}
		s, addErr := other.pc.AddTrack(local)
		if addErr != nil {
			log.Printf("voice: AddTrack to %s: %v", other.nick, addErr)
			continue
		}
		other.mu.Lock()
		other.subSenders[p.nick+"|"+kind] = s
		other.mu.Unlock()
	}
	p.room.mu.RUnlock()

	// Pump RTP.
	buf := make([]byte, 1500)
	for {
		n, _, readErr := remote.Read(buf)
		if readErr != nil {
			return
		}
		if _, writeErr := local.Write(buf[:n]); writeErr != nil {
			if errors.Is(writeErr, webrtc.ErrConnectionClosed) {
				return
			}
		}
	}
}

func (p *voicePeer) close() {
	if p.pc != nil {
		_ = p.pc.Close()
	}
}

func (m *voiceManager) handleLeave(nick, channel string) {
	m.mu.RLock()
	room, ok := m.rooms[channel]
	m.mu.RUnlock()
	if !ok {
		return
	}
	room.mu.Lock()
	peer, ok := room.peers[nick]
	if !ok {
		room.mu.Unlock()
		return
	}
	delete(room.peers, nick)
	// Detach this peer's published tracks from everyone else's PC
	// so they stop reading/sending.
	for _, other := range room.peers {
		other.mu.Lock()
		for key, sender := range other.subSenders {
			if strings.HasPrefix(key, nick+"|") {
				_ = other.pc.RemoveTrack(sender)
				delete(other.subSenders, key)
			}
		}
		other.mu.Unlock()
	}
	empty := len(room.peers) == 0
	room.mu.Unlock()

	peer.close()

	m.broadcast(channel, nick, signalEnvelope{
		Type:    "presence",
		Member:  nick,
		State:   "left",
		Channel: channel,
	})

	if empty {
		m.reapEmpty(channel)
	}
}

func (m *voiceManager) handleOffer(nick, channel, sdp string) {
	room, peer := m.lookup(nick, channel)
	if peer == nil {
		m.send(nick, signalEnvelope{Type: "error", Error: "not_in_room"})
		return
	}
	_ = room
	if err := peer.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: sdp,
	}); err != nil {
		m.send(nick, signalEnvelope{Type: "error",
			Error: "set_remote: " + err.Error()})
		return
	}
	answer, err := peer.pc.CreateAnswer(nil)
	if err != nil {
		m.send(nick, signalEnvelope{Type: "error",
			Error: "create_answer: " + err.Error()})
		return
	}
	if err := peer.pc.SetLocalDescription(answer); err != nil {
		m.send(nick, signalEnvelope{Type: "error",
			Error: "set_local: " + err.Error()})
		return
	}
	m.send(nick, signalEnvelope{Type: "answer", SDP: answer.SDP})
}

func (m *voiceManager) handleICE(nick, channel string, env signalEnvelope) {
	_, peer := m.lookup(nick, channel)
	if peer == nil {
		return
	}
	cand := webrtc.ICECandidateInit{Candidate: env.Candidate}
	if env.SDPMid != "" {
		mid := env.SDPMid
		cand.SDPMid = &mid
	}
	if env.SDPMLineIndex != nil {
		cand.SDPMLineIndex = env.SDPMLineIndex
	}
	_ = peer.pc.AddICECandidate(cand)
}

func (m *voiceManager) handleState(nick, channel string, env signalEnvelope) {
	// State (mute/cam/speaking/etc) is presence -- just rebroadcast
	// to everyone in the room.
	_, peer := m.lookup(nick, channel)
	if peer == nil {
		return
	}
	m.broadcast(channel, "", signalEnvelope{
		Type:    "presence",
		Member:  nick,
		State:   env.State,
		Channel: channel,
	})
}

func (m *voiceManager) lookup(nick, channel string) (*voiceRoom, *voicePeer) {
	m.mu.RLock()
	room, ok := m.rooms[channel]
	m.mu.RUnlock()
	if !ok {
		return nil, nil
	}
	room.mu.RLock()
	peer := room.peers[nick]
	room.mu.RUnlock()
	return room, peer
}

func (m *voiceManager) send(target string, env signalEnvelope) {
	if m.outbound == nil {
		return
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return
	}
	if err := m.outbound(target, string(payload)); err != nil {
		log.Printf("voice: outbound to %s: %v", target, err)
	}
}

// broadcast sends to everyone in `channel` except optional excludeNick.
// `excludeNick` of "" sends to every member.  We deliberately address
// the channel rather than enumerating recipients here because the
// IRCd is the natural broadcaster -- it already has the channel
// membership and can fan TAGMSG out cheaply.
func (m *voiceManager) broadcast(channel, _excludeNick string, env signalEnvelope) {
	if m.outbound == nil {
		return
	}
	payload, err := json.Marshal(env)
	if err != nil {
		return
	}
	_ = m.outbound(channel, string(payload))
}

func firstStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

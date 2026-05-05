// voice_bridge.go -- newline-delimited JSON over Unix socket between
// obbyircd's voice module and the SFU in this process.
//
// This is the *only* path between IRC and the media server.  The IRCd
// module serializes incoming TAGMSGs from clients into bridge messages
// (op="signal"), and writes outbound messages back to the wire as
// `:server.name TAGMSG <target> @+obsidianirc/rtc=<json>`.
//
// Only one bridge connection is expected at a time -- obbyircd, on
// the same host.  We accept one and reject extra connections; if the
// IRCd reconnects, the old session is replaced.
//
// Wire frames:
//
//   IRCd → backend:
//     {"op":"signal","from":"alice","channel":"^general","payload":{…}}
//     {"op":"part","from":"alice","channel":"^general"}
//     {"op":"quit","from":"alice"}        # client fully disconnected
//
//   backend → IRCd:
//     {"op":"signal","to":"alice","payload":{…}}    # direct
//     {"op":"signal","to":"^general","payload":{…}} # broadcast to channel
//
// The IRCd is responsible for translating "to":"^channel" into a
// fan-out across that channel's members (it already has the
// membership list).

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type bridgeFrame struct {
	Op string `json:"op"`

	// IRCd -> backend
	From    string          `json:"from,omitempty"`
	Account string          `json:"account,omitempty"`
	Channel string          `json:"channel,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`

	// backend -> IRCd
	To string `json:"to,omitempty"`
}

type voiceBridge struct {
	cfg VoiceConfig
	mgr *voiceManager

	mu     sync.Mutex
	conn   net.Conn
	writer *bufio.Writer

	// connEpoch identifies the current bridge connection; sends after
	// a reconnect on an old conn pointer become no-ops via the epoch
	// check.
	connEpoch atomic.Uint64

	// Reassembly buffers for chunked SDP signals (offer / answer).
	// Keyed by sender-nick + chunk-id; entries are dropped on
	// completion or reset on bridge reconnect.
	chunkMu  sync.Mutex
	chunkBuf map[string]*sdpChunkBuf
}

type sdpChunkBuf struct {
	parts    []string
	received int
	template signalEnvelope // metadata copied from chunk #0
}

func newVoiceBridge(cfg VoiceConfig, mgr *voiceManager) *voiceBridge {
	return &voiceBridge{
		cfg:      cfg,
		mgr:      mgr,
		chunkBuf: map[string]*sdpChunkBuf{},
	}
}

// assembleChunk collects a chunked SDP envelope. Returns a non-nil
// envelope (with the full SDP and chunk metadata stripped) once all
// pieces have arrived; returns nil while still waiting for more.
func (b *voiceBridge) assembleChunk(from string, env signalEnvelope) *signalEnvelope {
	if env.ChunkID == "" || env.Total == nil || env.Seq == nil || *env.Total <= 0 {
		// Not chunked. Return as-is.
		copy := env
		return &copy
	}
	key := from + "\x00" + env.ChunkID
	b.chunkMu.Lock()
	defer b.chunkMu.Unlock()
	buf := b.chunkBuf[key]
	if buf == nil {
		buf = &sdpChunkBuf{
			parts:    make([]string, *env.Total),
			template: env,
		}
		b.chunkBuf[key] = buf
	}
	if *env.Seq < 0 || *env.Seq >= len(buf.parts) {
		log.Printf("voice: chunk seq %d out of range (total=%d)", *env.Seq, len(buf.parts))
		delete(b.chunkBuf, key)
		return nil
	}
	if buf.parts[*env.Seq] != "" {
		// Duplicate chunk -- ignore.
		return nil
	}
	buf.parts[*env.Seq] = env.SDP
	buf.received++
	if buf.received < len(buf.parts) {
		return nil
	}
	delete(b.chunkBuf, key)
	full := buf.template
	full.SDP = strings.Join(buf.parts, "")
	full.ChunkID = ""
	full.Seq = nil
	full.Total = nil
	return &full
}

func (b *voiceBridge) listenAndServe(ctx context.Context) error {
	if err := os.RemoveAll(b.cfg.BridgeSocket); err != nil && !os.IsNotExist(err) {
		return err
	}
	ln, err := net.Listen("unix", b.cfg.BridgeSocket)
	if err != nil {
		return err
	}
	// Allow obbyircd (running as a different user) to connect.
	_ = os.Chmod(b.cfg.BridgeSocket, 0o666)
	log.Printf("voice: bridge listening on unix:%s", b.cfg.BridgeSocket)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	// Wire the SFU's outbound channel to whatever the active bridge
	// connection happens to be.
	b.mgr.outbound = b.send

	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go b.handleConn(c)
	}
}

func (b *voiceBridge) handleConn(c net.Conn) {
	defer c.Close()
	b.mu.Lock()
	if b.conn != nil {
		_ = b.conn.Close()
	}
	b.conn = c
	b.writer = bufio.NewWriter(c)
	epoch := b.connEpoch.Add(1)
	b.mu.Unlock()
	log.Printf("voice: bridge accepted (epoch %d)", epoch)

	scanner := bufio.NewScanner(c)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var f bridgeFrame
		if err := json.Unmarshal(scanner.Bytes(), &f); err != nil {
			log.Printf("voice: bridge bad frame: %v", err)
			continue
		}
		b.dispatch(f)
	}
	b.mu.Lock()
	if b.connEpoch.Load() == epoch {
		b.conn = nil
		b.writer = nil
	}
	b.mu.Unlock()
	log.Printf("voice: bridge closed (epoch %d)", epoch)
}

func (b *voiceBridge) dispatch(f bridgeFrame) {
	switch f.Op {
	case "signal":
		var raw signalEnvelope
		if err := json.Unmarshal(f.Payload, &raw); err != nil {
			log.Printf("voice: signal payload: %v", err)
			return
		}
		// Reassemble chunked SDP signals (offer / answer split by the
		// client to fit under CLIENT_TAG_SIZE_LIMIT). Non-chunked
		// envelopes return immediately as-is.
		envPtr := b.assembleChunk(f.From, raw)
		if envPtr == nil {
			return
		}
		env := *envPtr
		log.Printf("voice: signal type=%q from=%s ch=%s sdpLen=%d candLen=%d",
			env.Type, f.From, f.Channel, len(env.SDP), len(env.Candidate))
		switch env.Type {
		case "join":
			b.mgr.handleJoin(f.From, env.Channel, f.Account)
		case "leave":
			b.mgr.handleLeave(f.From, env.Channel)
		case "offer":
			b.mgr.handleOffer(f.From, f.Channel, env.SDP)
		case "answer":
			b.mgr.handleClientAnswer(f.From, f.Channel, env.SDP)
		case "ice":
			b.mgr.handleICE(f.From, f.Channel, env)
		case "mic", "video", "speaking", "silent", "deaf", "screen", "hand":
			b.mgr.handleState(f.From, f.Channel, env)
		case "react":
			b.mgr.handleReaction(f.From, f.Channel, env)
		default:
			log.Printf("voice: unknown signal type %q", env.Type)
		}
	case "part", "quit":
		// IRCd informs us a client left a voice channel or quit
		// IRC entirely -- tear down their SFU peer if any.
		if f.Channel != "" {
			b.mgr.handleLeave(f.From, f.Channel)
			return
		}
		// Quit: scrub them from every room.
		b.mgr.mu.RLock()
		channels := make([]string, 0, len(b.mgr.rooms))
		for ch, room := range b.mgr.rooms {
			room.mu.RLock()
			if _, in := room.peers[f.From]; in {
				channels = append(channels, ch)
			}
			room.mu.RUnlock()
		}
		b.mgr.mu.RUnlock()
		for _, ch := range channels {
			b.mgr.handleLeave(f.From, ch)
		}
	default:
		log.Printf("voice: unknown bridge op %q", f.Op)
	}
}

// send writes a backend->IRCd frame.  Safe to call from any goroutine
// (signal callbacks fire from pion's read goroutines).
func (b *voiceBridge) send(target, payload string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.writer == nil {
		return errors.New("bridge not connected")
	}
	frame := bridgeFrame{
		Op:      "signal",
		To:      target,
		Payload: json.RawMessage(payload),
	}
	encoded, err := json.Marshal(frame)
	if err != nil {
		return err
	}
	if _, err := b.writer.Write(encoded); err != nil {
		return err
	}
	if err := b.writer.WriteByte('\n'); err != nil {
		return err
	}
	// Flush deliberately on every frame.  Bridge traffic is sparse,
	// and signaling latency matters more than throughput.
	if err := b.writer.Flush(); err != nil {
		return err
	}
	return nil
}

// startVoiceSubsystem boots TURN + bridge.  Returns a teardown func.
// Errors from individual sub-systems are logged but don't fail the
// whole backend; if VOICE_TURN_SECRET isn't set we simply skip voice
// initialization.
func startVoiceSubsystem(ctx context.Context) func() {
	cfg := loadVoiceConfig()
	if cfg.TurnAuthSecret == "" {
		log.Printf("voice: VOICE_TURN_SECRET unset; voice subsystem disabled")
		return func() {}
	}

	turnSrv, err := startTurnServer(cfg)
	if err != nil {
		log.Printf("voice: TURN startup: %v", err)
		return func() {}
	}

	mgr := newVoiceManager(cfg)
	bridge := newVoiceBridge(cfg, mgr)
	go func() {
		if err := bridge.listenAndServe(ctx); err != nil {
			log.Printf("voice: bridge: %v", err)
		}
	}()

	return func() {
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(), 5*time.Second)
		defer cancel()
		_ = turnSrv.Close()
		<-shutdownCtx.Done()
	}
}

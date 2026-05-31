package orca

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/pion/rtp"
)

// Video playback constants. Tuned for the SFU's clients (browsers
// expect VP8 at 90 kHz, ~30fps, RFC 7741 packetization). 800 kbps
// + 640x360 keeps the per-frame size small enough that fragmentation
// stays cheap and the public bandwidth bill stays sane.
const (
	vp8PayloadType  = 96   // matches the negotiated VP8 PT in SDP
	vp8ClockRate    = 90000
	vp8MTU          = 1200 // safe RTP payload size after IP/UDP headers
	videoFrameHz    = 30
	videoMaxSeconds = 600  // 10-minute hard cap
)

// videoPlayer manages one in-flight ffmpeg pipeline for a channel.
// Cancel via cancel(); wait on done for cleanup completion. One
// instance per channel max -- a new play_video preempts any prior one.
type videoPlayer struct {
	url     string
	cancel  context.CancelFunc
	done    chan struct{}
	started time.Time
}

// playVideo starts a new video playback in `channel`, preempting any
// prior playback in the same channel. Returns immediately with the
// player handle (or error if ffmpeg / pipes / track aren't available).
// Real work happens in goroutines until ctx is cancelled, ffmpeg exits,
// or the duration cap is hit.
func (vs *voiceSubsystem) playVideo(parentCtx context.Context, channel, url string) error {
	if url == "" {
		return errors.New("url required")
	}
	if vs.tap == nil {
		return errors.New("voice tap not installed")
	}
	tap, ok := vs.tap.(*localTap)
	if !ok {
		return errors.New("video playback requires the SFU localTap (got nopVoiceTap)")
	}
	tap.mu.Lock()
	peer := tap.peers[channel]
	tap.mu.Unlock()
	if peer == nil {
		return fmt.Errorf("not joined to %s", channel)
	}

	// Preempt any in-flight playback for this channel.
	vs.stopVideo(channel)

	ctx, cancel := context.WithTimeout(parentCtx, videoMaxSeconds*time.Second)
	player := &videoPlayer{
		url:     url,
		cancel:  cancel,
		done:    make(chan struct{}),
		started: time.Now(),
	}
	vs.videoMu.Lock()
	if vs.activeVideo == nil {
		vs.activeVideo = map[string]*videoPlayer{}
	}
	vs.activeVideo[channel] = player
	vs.videoMu.Unlock()

	go func() {
		defer close(player.done)
		defer cancel()
		defer func() {
			vs.videoMu.Lock()
			if vs.activeVideo[channel] == player {
				delete(vs.activeVideo, channel)
			}
			vs.videoMu.Unlock()
		}()
		if err := vs.runVideoPipeline(ctx, channel, url, peer); err != nil {
			log.Printf("[orca/video] %s: playback ended: %v", channel, err)
		} else {
			log.Printf("[orca/video] %s: playback finished cleanly", channel)
		}
	}()
	return nil
}

// stopVideo cancels any active playback in `channel`. Returns whether
// something was actually cancelled (false if nothing was playing).
func (vs *voiceSubsystem) stopVideo(channel string) bool {
	vs.videoMu.Lock()
	p, ok := vs.activeVideo[channel]
	if ok {
		delete(vs.activeVideo, channel)
	}
	vs.videoMu.Unlock()
	if !ok || p == nil {
		return false
	}
	p.cancel()
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		// ffmpeg sometimes takes a moment to honor SIGTERM/Kill;
		// drop the handle and move on.
	}
	return true
}

// runVideoPipeline spawns one ffmpeg that demuxes the URL into VP8
// (on stdout, IVF format) + 48 kHz stereo s16le PCM (on fd 3 via
// ExtraFiles). Two reader goroutines packetize each stream into RTP
// and write through the persistent encoder/packetizer per peer.
func (vs *voiceSubsystem) runVideoPipeline(ctx context.Context, channel, url string, peer LocalPeer) error {
	audioR, audioW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer audioR.Close()

	cmd := exec.CommandContext(ctx, "ffmpeg",
		"-hide_banner",
		"-loglevel", "error",
		"-nostdin",
		"-i", url,
		// Video output: VP8 in IVF on stdout. Scale to 640x360 and cap
		// to 30 fps so per-frame size stays small and pacing is sane.
		"-an",
		"-vf", "scale=640:360,fps=30",
		"-c:v", "libvpx",
		"-b:v", "800k",
		"-cpu-used", "8",
		"-deadline", "realtime",
		"-auto-alt-ref", "0",
		"-g", "30",
		"-keyint_min", "30",
		"-error-resilient", "1",
		"-f", "ivf", "pipe:1",
		// Audio output: 48 kHz stereo s16le on fd 3. We feed the raw
		// PCM straight into the existing Opus encoder + RTP packetizer
		// path, so the audio shares the same SSRC as TTS/voice replies.
		"-vn",
		"-c:a", "pcm_s16le",
		"-ac", "2",
		"-ar", "48000",
		"-f", "s16le", "pipe:3",
	)
	cmd.ExtraFiles = []*os.File{audioW}
	cmd.Stderr = os.Stderr

	videoStdout, err := cmd.StdoutPipe()
	if err != nil {
		audioW.Close()
		return fmt.Errorf("stdout pipe: %w", err)
	}

	log.Printf("[orca/video] %s: spawning ffmpeg for %s", channel, url)
	if err := cmd.Start(); err != nil {
		audioW.Close()
		return fmt.Errorf("ffmpeg start: %w", err)
	}
	// Parent's copy of audioW must be closed so EOF on audioR fires
	// when the child exits. Child kept its dup via ExtraFiles.
	_ = audioW.Close()

	// Pull the persistent encoder + packetizers for this channel from
	// localTap; audio packetizer is shared with TTS so the SSRC stays
	// stable. Video gets its own packetizer (fresh SSRC) the first time
	// it's used per channel.
	tap, _ := vs.tap.(*localTap)
	tap.mu.Lock()
	if tap.pktrs == nil {
		tap.pktrs = map[string]*RTPPacketizer{}
	}
	if tap.encs == nil {
		tap.encs = map[string]*OpusEncoder{}
	}
	audioPktr := tap.pktrs[channel]
	if audioPktr == nil {
		audioPktr = NewRTPPacketizer(NextSSRC())
		tap.pktrs[channel] = audioPktr
	}
	audioEnc := tap.encs[channel]
	if audioEnc == nil {
		enc, eerr := NewOpusEncoder()
		if eerr != nil {
			_ = cmd.Process.Kill()
			tap.mu.Unlock()
			return fmt.Errorf("opus encoder: %w", eerr)
		}
		audioEnc = enc
		tap.encs[channel] = audioEnc
	}
	tap.mu.Unlock()
	videoPktr := newVP8Packetizer(NextSSRC())

	peer.BroadcastSpeaking()
	defer peer.BroadcastSilent()

	// Run both pumps. The first to return (or ctx cancel) tears down
	// the rest by killing ffmpeg, which fires EOF on the other pipe.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := pumpVideoIVF(ctx, videoStdout, peer, videoPktr); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("[orca/video] %s: video pump: %v", channel, err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := pumpAudioPCM(ctx, audioR, peer, audioEnc, audioPktr); err != nil && !errors.Is(err, io.EOF) {
			log.Printf("[orca/video] %s: audio pump: %v", channel, err)
		}
	}()
	wg.Wait()
	_ = cmd.Wait()
	return nil
}

// ----- IVF reader + VP8 RTP packetizer -----------------------------

type ivfReader struct {
	r          io.Reader
	timebaseN  uint32
	timebaseD  uint32
	firstFrame bool
}

// readIVFHeader parses the 32-byte IVF container header and returns
// the timebase (used for PTS interpretation downstream).
func readIVFHeader(r io.Reader) (*ivfReader, error) {
	var h [32]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, fmt.Errorf("ivf header: %w", err)
	}
	if string(h[0:4]) != "DKIF" {
		return nil, fmt.Errorf("ivf: missing DKIF signature")
	}
	if string(h[8:12]) != "VP80" {
		return nil, fmt.Errorf("ivf: not VP8 (got %q)", h[8:12])
	}
	tbD := binary.LittleEndian.Uint32(h[16:20])
	tbN := binary.LittleEndian.Uint32(h[20:24])
	return &ivfReader{r: r, timebaseN: tbN, timebaseD: tbD, firstFrame: true}, nil
}

// readFrame returns the next VP8 frame bytes and its 64-bit PTS.
func (ir *ivfReader) readFrame() ([]byte, uint64, error) {
	var fh [12]byte
	if _, err := io.ReadFull(ir.r, fh[:]); err != nil {
		return nil, 0, err
	}
	sz := binary.LittleEndian.Uint32(fh[0:4])
	pts := binary.LittleEndian.Uint64(fh[4:12])
	if sz == 0 || sz > 2_000_000 {
		return nil, 0, fmt.Errorf("ivf: bogus frame size %d", sz)
	}
	buf := make([]byte, sz)
	if _, err := io.ReadFull(ir.r, buf); err != nil {
		return nil, 0, err
	}
	return buf, pts, nil
}

type vp8Packetizer struct {
	mu   sync.Mutex
	ssrc uint32
	seq  uint16
	ts   uint32
}

func newVP8Packetizer(ssrc uint32) *vp8Packetizer {
	return &vp8Packetizer{ssrc: ssrc}
}

// packetize splits one VP8 frame into RFC 7741 RTP packets.
// payloadTs is the 90kHz RTP timestamp for this frame; all fragments
// of one frame share the same ts. Marker bit is set on the last
// fragment of the frame.
func (p *vp8Packetizer) packetize(frame []byte, payloadTs uint32) [][]byte {
	const descByte = 0x00 // X=0 R=0 N=0 S=0 PartID=0 (start handled below)
	maxPayload := vp8MTU - 1 // 1 byte for VP8 payload descriptor
	out := [][]byte{}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.ts = payloadTs

	for off := 0; off < len(frame); off += maxPayload {
		end := off + maxPayload
		if end > len(frame) {
			end = len(frame)
		}
		isLast := end == len(frame)
		desc := byte(descByte)
		if off == 0 {
			desc |= 0x10 // S bit (start of partition)
		}
		payload := make([]byte, 1+(end-off))
		payload[0] = desc
		copy(payload[1:], frame[off:end])

		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    vp8PayloadType,
				SequenceNumber: p.seq,
				Timestamp:      p.ts,
				SSRC:           p.ssrc,
				Marker:         isLast,
			},
			Payload: payload,
		}
		raw, err := pkt.Marshal()
		if err == nil {
			out = append(out, raw)
		}
		p.seq++
	}
	return out
}

// pumpVideoIVF reads VP8 frames out of the ffmpeg ivf stream and
// dispatches them at real-time pace. Uses IVF PTS for timing.
func pumpVideoIVF(ctx context.Context, r io.Reader, peer LocalPeer, pktr *vp8Packetizer) error {
	ir, err := readIVFHeader(r)
	if err != nil {
		return err
	}

	// Convert IVF PTS (units of timebase) → 90 kHz RTP timestamp.
	tbN := uint64(ir.timebaseN)
	tbD := uint64(ir.timebaseD)
	if tbN == 0 {
		tbN = 1
	}
	if tbD == 0 {
		tbD = videoFrameHz
	}
	ptsToRTP := func(pts uint64) uint32 {
		return uint32(pts * uint64(vp8ClockRate) * tbN / tbD)
	}
	ptsToDuration := func(pts uint64) time.Duration {
		return time.Duration(pts*uint64(time.Second)*tbN/tbD) * time.Nanosecond / time.Nanosecond
	}

	playStart := time.Now()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		frame, pts, err := ir.readFrame()
		if err != nil {
			return err
		}
		// Pace by PTS: sleep until the frame's playback time arrives.
		target := playStart.Add(ptsToDuration(pts))
		if d := time.Until(target); d > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
			}
		}
		pkts := pktr.packetize(frame, ptsToRTP(pts))
		for _, pkt := range pkts {
			if err := peer.SendVideoRTP(pkt); err != nil {
				return err
			}
		}
	}
}

// pumpAudioPCM reads 48kHz stereo s16le PCM from r, encodes to Opus
// in 20ms frames, and writes RTP packets via the shared audio
// packetizer. Real-time pacing via the deadline pattern used by
// speakOpus elsewhere.
func pumpAudioPCM(ctx context.Context, r io.Reader, peer LocalPeer, enc *OpusEncoder, pktr *RTPPacketizer) error {
	const (
		samplesPerFrame = opusSamplesFrame * opusChannels // 1920 int16 per 20 ms
		bytesPerFrame   = samplesPerFrame * 2
	)
	frameInterval := time.Duration(opusFrameMs) * time.Millisecond
	deadline := time.Now()
	buf := make([]byte, bytesPerFrame)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		pcm := make([]int16, samplesPerFrame)
		for i := range pcm {
			pcm[i] = int16(binary.LittleEndian.Uint16(buf[2*i:]))
		}
		payload, err := enc.EncodeFrame(pcm)
		if err != nil {
			return err
		}
		rtpBytes, err := pktr.Wrap(payload)
		if err != nil {
			return err
		}
		if err := peer.SendOpus(rtpBytes); err != nil {
			return err
		}
		deadline = deadline.Add(frameInterval)
		if d := time.Until(deadline); d > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(d):
			}
		} else {
			deadline = time.Now()
		}
	}
}

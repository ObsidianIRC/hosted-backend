package orca

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/hajimehoshi/go-mp3"
	"github.com/pion/rtp"
	opus "gopkg.in/hraban/opus.v2"
)

// Opus WebRTC convention: 48 kHz, stereo, 20 ms frames.
const (
	opusSampleRate    = 48000
	opusChannels      = 2
	opusFrameMs       = 20
	opusSamplesFrame  = opusSampleRate * opusFrameMs / 1000 // 960 per channel
	opusPayloadType   = 111
)

// OpusDecoder turns Opus RTP payload bytes back into 16-bit PCM at
// 48 kHz stereo.  Safe for sequential use only; one per speaker.
type OpusDecoder struct {
	dec *opus.Decoder
}

func NewOpusDecoder() (*OpusDecoder, error) {
	d, err := opus.NewDecoder(opusSampleRate, opusChannels)
	if err != nil {
		return nil, err
	}
	return &OpusDecoder{dec: d}, nil
}

// Decode takes one Opus packet (the payload of one RTP packet) and
// returns interleaved 16-bit PCM samples.
func (d *OpusDecoder) Decode(opusPayload []byte) ([]int16, error) {
	pcm := make([]int16, opusSamplesFrame*opusChannels)
	n, err := d.dec.Decode(opusPayload, pcm)
	if err != nil {
		return nil, err
	}
	return pcm[:n*opusChannels], nil
}

// OpusEncoder takes 48 kHz stereo PCM and produces RTP-ready Opus
// payload bytes.  Safe for sequential use only; one per outbound stream.
type OpusEncoder struct {
	enc *opus.Encoder
	buf []byte
}

func NewOpusEncoder() (*OpusEncoder, error) {
	e, err := opus.NewEncoder(opusSampleRate, opusChannels, opus.AppVoIP)
	if err != nil {
		return nil, err
	}
	return &OpusEncoder{enc: e, buf: make([]byte, 4000)}, nil
}

// EncodeFrame takes exactly one 20 ms frame of 48 kHz stereo PCM
// (1920 samples interleaved) and returns its Opus payload.
func (e *OpusEncoder) EncodeFrame(pcm []int16) ([]byte, error) {
	if len(pcm) != opusSamplesFrame*opusChannels {
		return nil, fmt.Errorf("expected %d samples, got %d",
			opusSamplesFrame*opusChannels, len(pcm))
	}
	n, err := e.enc.Encode(pcm, e.buf)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, e.buf[:n])
	return out, nil
}

// RTPPacketizer wraps an Opus stream with monotonically-increasing
// sequence numbers and timestamps so the SFU treats it as a coherent
// stream.  One per outbound source.
type RTPPacketizer struct {
	mu       sync.Mutex
	ssrc     uint32
	seq      uint16
	ts       uint32
	tsStep   uint32
}

func NewRTPPacketizer(ssrc uint32) *RTPPacketizer {
	return &RTPPacketizer{
		ssrc:   ssrc,
		ts:     0,
		tsStep: opusSamplesFrame, // 960 ticks per 20 ms frame at 48 kHz
	}
}

func (p *RTPPacketizer) Wrap(opusPayload []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    opusPayloadType,
			SequenceNumber: p.seq,
			Timestamp:      p.ts,
			SSRC:           p.ssrc,
			Marker:         p.seq == 0,
		},
		Payload: opusPayload,
	}
	out, err := pkt.Marshal()
	if err != nil {
		return nil, err
	}
	p.seq++
	p.ts += p.tsStep
	return out, nil
}

// DepacketizeOpus strips the RTP header off an inbound packet and
// returns the Opus payload + the publishing SSRC for stream demuxing.
func DepacketizeOpus(rtpBytes []byte) (payload []byte, ssrc uint32, err error) {
	pkt := &rtp.Packet{}
	if err := pkt.Unmarshal(rtpBytes); err != nil {
		return nil, 0, err
	}
	return pkt.Payload, pkt.SSRC, nil
}

// DecodeMP3 fully decodes an MP3 byte stream to interleaved 16-bit PCM.
// hajimehoshi/go-mp3 always outputs 44.1 kHz / 48 kHz stereo (depending
// on source), so the caller may need to resample / mono-mix.  The
// returned sample rate is the decoder's native rate.
func DecodeMP3(mp3Bytes []byte) (pcm []int16, sampleRate int, err error) {
	d, err := mp3.NewDecoder(bytes.NewReader(mp3Bytes))
	if err != nil {
		return nil, 0, err
	}
	sampleRate = d.SampleRate()
	raw, err := io.ReadAll(d)
	if err != nil {
		return nil, 0, err
	}
	// go-mp3 yields little-endian int16 stereo.
	pcm = make([]int16, len(raw)/2)
	for i := range pcm {
		pcm[i] = int16(binary.LittleEndian.Uint16(raw[i*2:]))
	}
	return pcm, sampleRate, nil
}

// MonoToStereo duplicates each sample so an Opus encoder expecting
// stereo input gets a balanced stream.
func MonoToStereo(mono []int16) []int16 {
	out := make([]int16, len(mono)*2)
	for i, s := range mono {
		out[2*i] = s
		out[2*i+1] = s
	}
	return out
}

// StereoToMono averages L+R for STT or VAD that prefers mono input.
func StereoToMono(stereo []int16) []int16 {
	out := make([]int16, len(stereo)/2)
	for i := range out {
		out[i] = int16((int32(stereo[2*i]) + int32(stereo[2*i+1])) / 2)
	}
	return out
}

// Resample is a naive linear-interpolation resampler.  Good enough for
// speech; not for music.  Operates on stereo (interleaved) or mono.
func Resample(pcm []int16, fromHz, toHz, channels int) []int16 {
	if fromHz == toHz || len(pcm) == 0 {
		return pcm
	}
	srcFrames := len(pcm) / channels
	dstFrames := srcFrames * toHz / fromHz
	out := make([]int16, dstFrames*channels)
	for i := 0; i < dstFrames; i++ {
		srcPos := float64(i) * float64(fromHz) / float64(toHz)
		idx := int(srcPos)
		frac := srcPos - float64(idx)
		next := idx + 1
		if next >= srcFrames {
			next = srcFrames - 1
		}
		for c := 0; c < channels; c++ {
			a := float64(pcm[idx*channels+c])
			b := float64(pcm[next*channels+c])
			out[i*channels+c] = int16(a + (b-a)*frac)
		}
	}
	return out
}

// RMS energy on int16 PCM, for cheap silence detection.
func PCMRMS(pcm []int16) float64 {
	if len(pcm) == 0 {
		return 0
	}
	var sumSq float64
	for _, s := range pcm {
		v := float64(s)
		sumSq += v * v
	}
	return sumSq / float64(len(pcm))
}

// ssrcSeed gives every outbound packetizer a stable, unique SSRC so the
// SFU treats the local participant's audio as one coherent stream.
var ssrcSeed uint32

func NextSSRC() uint32 {
	return atomic.AddUint32(&ssrcSeed, 1) | 0xa0000000
}

package main

import (
	"context"

	"backend/orca"
)

type ircAdapter struct{}

func (ircAdapter) Query(ctx context.Context, method string, params map[string]any) (any, error) {
	return ircQuery(method, params)
}

var _ orca.IRC = ircAdapter{}

// voiceAPIAdapter bridges *voiceManager's RegisterLocal to
// orca.LocalParticipantAPI without crossing the package boundary in
// either direction. orca holds a mirror interface; we wrap the returned
// LocalPeer here so the method-set lines up structurally.
type voiceAPIAdapter struct {
	mgr *voiceManager
}

func (a voiceAPIAdapter) RegisterLocal(nick, channel string, onRTP orca.LocalRTPCallback) (orca.LocalPeer, error) {
	if a.mgr == nil {
		return nil, errVoiceMgrNil
	}
	cb := RTPCallback(func(speaker, kind string, payload []byte) {
		onRTP(speaker, kind, payload)
	})
	peer, err := a.mgr.RegisterLocal(nick, channel, cb)
	if err != nil {
		return nil, err
	}
	return localPeerAdapter{inner: peer}, nil
}

type localPeerAdapter struct{ inner LocalPeer }

func (a localPeerAdapter) SendOpus(pkt []byte) error { return a.inner.SendOpus(pkt) }
func (a localPeerAdapter) Stop() error               { return a.inner.Stop() }
func (a localPeerAdapter) BroadcastSpeaking()        { a.inner.BroadcastSpeaking() }
func (a localPeerAdapter) BroadcastSilent()          { a.inner.BroadcastSilent() }

var errVoiceMgrNil = errVoiceMgrNilError{}

type errVoiceMgrNilError struct{}

func (errVoiceMgrNilError) Error() string { return "voice subsystem not running" }

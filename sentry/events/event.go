// Package events defines the on-the-wire shape of IRC behavioural
// events emitted by obbyircd's sentinel.c module and consumed by the
// sentry detection pipeline. Carved into its own subpackage so the
// rule layer (sentry/heuristics) and the manager (sentry) can both
// import it without an import cycle.
package events

import (
	"encoding/json"
	"time"
)

// EventKind enumerates the structured events sentinel.c emits.
// New kinds need to be added BOTH here and in sentinel.c's switch.
type EventKind string

const (
	EventConnect    EventKind = "connect"     // local client TCP/TLS accepted, before NICK/USER
	EventRegister   EventKind = "register"    // client completed registration (NICK+USER done)
	EventQuit       EventKind = "quit"        // client disconnected (any reason)
	EventJoin       EventKind = "join"        // user joined a channel
	EventPart       EventKind = "part"        // user parted a channel
	EventKick       EventKind = "kick"        // user was kicked from a channel
	EventNick       EventKind = "nick"        // user changed nick
	EventChanMsg    EventKind = "chanmsg"     // PRIVMSG to channel
	EventChanNotice EventKind = "channotice"  // NOTICE to channel
	EventUserMsg    EventKind = "usermsg"     // PRIVMSG to another user
	EventCTCP       EventKind = "ctcp"        // CTCP request/reply (channel or user)
	EventMode       EventKind = "mode"        // channel or user mode change
	EventOperKill   EventKind = "oper_kill"   // /KILL by an oper -- positive label
	EventOperKline  EventKind = "oper_kline"  // K/G/Z-line set by an oper -- positive label
	EventOperKick   EventKind = "oper_kick"   // /KICK by an oper -- positive label
)

// Event is the on-the-wire shape. All fields are optional; which ones
// are populated depends on Kind. Time is set by sentinel.c at emit
// time so sentry can reason about real arrival cadence even if its
// own consumption is bursty.
type Event struct {
	Kind EventKind `json:"kind"`
	Time int64     `json:"t"` // unix milliseconds

	// Subject of the event (the user "doing" it).
	Nick    string `json:"nick,omitempty"`
	Ident   string `json:"ident,omitempty"`
	Host    string `json:"host,omitempty"`
	IP      string `json:"ip,omitempty"`
	Account string `json:"account,omitempty"`
	UID     string `json:"uid,omitempty"`     // server-assigned ID (more stable than nick)
	IsTLS   bool   `json:"tls,omitempty"`

	// Channel context (when applicable).
	Channel string `json:"channel,omitempty"`

	// Target context (for kick/usermsg/mode-on-user).
	TargetNick string `json:"target,omitempty"`

	// Message payload (for chanmsg/usermsg/channotice/ctcp).
	// NEVER sent to external services; the sentry pipeline strips
	// this before any tool emission to Orca and the LLM gate L4 has
	// been deliberately removed from the design.
	Text string `json:"text,omitempty"`

	// Mode-change payload.
	ModeString string   `json:"mode,omitempty"`
	ModeArgs   []string `json:"mode_args,omitempty"`

	// Oper action context (only on oper_* kinds).
	Oper        string `json:"oper,omitempty"`         // who performed the action
	Reason      string `json:"reason,omitempty"`       // reason string
	TargetIdent string `json:"target_ident,omitempty"` // for kline-like, the masked user@host
	TargetHost  string `json:"target_host,omitempty"`
	BanType     string `json:"ban_type,omitempty"`     // "kline" / "gline" / "zline" etc.
}

// MarshalLine serializes one Event as a single line of JSON, ready
// for the sentinel.c Unix-socket protocol.
func (e *Event) MarshalLine() ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// IsOperLabel reports whether this event represents an oper decision
// that should feed the L3 training label store as a positive.
func (e *Event) IsOperLabel() bool {
	switch e.Kind {
	case EventOperKill, EventOperKline, EventOperKick:
		return true
	}
	return false
}

// At returns the event timestamp as a time.Time.
func (e *Event) At() time.Time {
	return time.UnixMilli(e.Time)
}

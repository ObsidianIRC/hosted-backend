package sentry

import (
	"sync"
	"testing"
	"time"

	"backend/sentry/events"
	"backend/sentry/heuristics"
)

// captureSink collects every alert the manager emits so test cases
// can make assertions about which heuristics fired.
type captureSink struct {
	mu     sync.Mutex
	alerts []heuristics.Alert
}

func (c *captureSink) Emit(alerts []heuristics.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alerts = append(c.alerts, alerts...)
}

func (c *captureSink) Kinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.alerts))
	for i, a := range c.alerts {
		out[i] = a.Kind
	}
	return out
}

func contains(kinds []string, want string) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

func mk(kind events.EventKind, at time.Time, fn func(*events.Event)) *events.Event {
	ev := &events.Event{Kind: kind, Time: at.UnixMilli()}
	if fn != nil {
		fn(ev)
	}
	return ev
}

// TestFloodTriggers fires 31 channel messages in a single second from
// one user; the flood rule (threshold 30/min) should trip.
func TestFloodTriggers(t *testing.T) {
	sink := &captureSink{}
	m := NewManager(WithSink(sink))
	now := time.Unix(1_700_000_000, 0)

	m.Observe(mk(events.EventConnect, now, func(e *events.Event) {
		e.UID = "u1"
		e.Nick = "spammer"
	}))
	for i := 0; i < 31; i++ {
		m.Observe(mk(events.EventChanMsg, now.Add(time.Duration(i)*time.Second/31), func(e *events.Event) {
			e.UID = "u1"
			e.Nick = "spammer"
			e.Channel = "#test"
			e.Text = "hello there"
		}))
	}
	if !contains(sink.Kinds(), "flood") {
		t.Fatalf("expected flood alert, got %v", sink.Kinds())
	}
}

// TestRepeatTriggers fires the same message 5 times. Repeat rule
// (threshold 4 duplicate hits) should trip.
func TestRepeatTriggers(t *testing.T) {
	sink := &captureSink{}
	m := NewManager(WithSink(sink))
	now := time.Unix(1_700_000_100, 0)

	m.Observe(mk(events.EventConnect, now, func(e *events.Event) {
		e.UID = "u2"
		e.Nick = "echo"
	}))
	for i := 0; i < 5; i++ {
		m.Observe(mk(events.EventChanMsg, now.Add(time.Duration(i)*time.Second), func(e *events.Event) {
			e.UID = "u2"
			e.Nick = "echo"
			e.Channel = "#test"
			e.Text = "BUY DOGECOIN NOW"
		}))
	}
	if !contains(sink.Kinds(), "repeat") {
		t.Fatalf("expected repeat alert, got %v", sink.Kinds())
	}
}

// TestMassJoinTriggers fires 11 joins from one user in a single
// minute. mass_join (threshold 10/min) should trip.
func TestMassJoinTriggers(t *testing.T) {
	sink := &captureSink{}
	m := NewManager(WithSink(sink))
	now := time.Unix(1_700_001_000, 0)

	m.Observe(mk(events.EventConnect, now, func(e *events.Event) {
		e.UID = "u3"
		e.Nick = "joiner"
	}))
	for i := 0; i < 11; i++ {
		m.Observe(mk(events.EventJoin, now.Add(time.Duration(i)*time.Second), func(e *events.Event) {
			e.UID = "u3"
			e.Nick = "joiner"
			e.Channel = "#c" + intToStrStub(i)
		}))
	}
	if !contains(sink.Kinds(), "mass_join") {
		t.Fatalf("expected mass_join alert, got %v", sink.Kinds())
	}
}

// TestLinkSpamTriggers: brand-new user posts a URL in their first
// channel message within 30 seconds of connect.
func TestLinkSpamTriggers(t *testing.T) {
	sink := &captureSink{}
	m := NewManager(WithSink(sink))
	now := time.Unix(1_700_002_000, 0)

	m.Observe(mk(events.EventConnect, now, func(e *events.Event) {
		e.UID = "u4"
		e.Nick = "drive_by"
	}))
	m.Observe(mk(events.EventChanMsg, now.Add(5*time.Second), func(e *events.Event) {
		e.UID = "u4"
		e.Nick = "drive_by"
		e.Channel = "#general"
		e.Text = "free vbucks https://totally-not-a-scam.example/click"
	}))
	if !contains(sink.Kinds(), "link_spam") {
		t.Fatalf("expected link_spam alert, got %v", sink.Kinds())
	}
}

// TestNormalChatDoesNotAlert: a well-behaved user sending occasional
// distinct messages must NOT trigger any rules.
func TestNormalChatDoesNotAlert(t *testing.T) {
	sink := &captureSink{}
	m := NewManager(WithSink(sink))
	now := time.Unix(1_700_003_000, 0)

	m.Observe(mk(events.EventConnect, now, func(e *events.Event) {
		e.UID = "u5"
		e.Nick = "regular"
		e.Account = "regular"
	}))
	for i := 0; i < 6; i++ {
		m.Observe(mk(events.EventChanMsg, now.Add(time.Duration(i*10)*time.Second), func(e *events.Event) {
			e.UID = "u5"
			e.Nick = "regular"
			e.Channel = "#general"
			e.Text = "thoughtful message number " + intToStrStub(i)
		}))
	}
	if len(sink.Kinds()) != 0 {
		t.Fatalf("expected no alerts for normal chat, got %v", sink.Kinds())
	}
}

// intToStrStub keeps the test file self-contained without importing
// strconv (matches the existing intToStr style used in heuristics).
func intToStrStub(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Package heuristics holds the L1 detection layer: fast, explainable,
// deterministic rules. Every rule returns Alerts with a numeric
// confidence in [0, 1] -- so the L1 layer can vote as a feature into
// L3, not just as a hard trigger.
//
// New rules go in their own file under this package and register via
// init() so the dispatcher picks them up automatically.
package heuristics

import (
	"strings"
	"sync"
	"time"

	"backend/sentry/events"
)

// Alert is the output of any detection rule. Multiple alerts can
// fire on a single event; the sentry pipeline aggregates them.
type Alert struct {
	Kind        string    // canonical name (e.g. "flood", "repeat", "mass_join")
	UID         string    // subject user (stable across nick changes)
	Nick        string    // current nick at time of alert (for display)
	Channel     string    // channel context if applicable
	Confidence  float64   // [0, 1]: how sure the rule is
	Evidence    string    // short human-readable string for #opers display
	At          time.Time
	TriggeredBy *events.Event // the event that fired the rule (nil-safe)
}

// Rule is the contract every L1 heuristic implements. Implementations
// MUST be safe to call from multiple goroutines.
type Rule interface {
	Name() string
	Observe(u UserSnapshot, ev *events.Event) []Alert
}

// UserSnapshot is the subset of per-user state we hand to rules.
// Decoupled from sentry.userState so rules can be unit-tested without
// the manager's bookkeeping.
type UserSnapshot struct {
	UID            string
	Nick           string
	FirstSeen      time.Time
	IsTLS          bool
	HasAccount     bool
	MsgCount       int
	JoinCount      int
	CTCPCount      int
	LastMsgAt      time.Time
	RecentMsgRate  float64 // messages/min over last 60s
	RecentJoinRate float64 // joins/min over last 60s
	DupHashCount   int     // count of duplicate hashes in recent window
	URLCount       int     // URLs in recent window
	UpperRatioMean float64 // avg uppercase ratio in recent window

	// BurstStartIdleGap is the idle duration that preceded the start
	// of the user's current burst. Zero outside an active burst.
	// Sticky as the burst continues -- the rule layer can rely on it
	// after several burst messages without losing the "they were
	// silent before this" signal.
	BurstStartIdleGap time.Duration

	// Behavioural counts over the recent 60s window.
	NickFlipRate float64 // nick changes / min
	HopRate      float64 // join+part actions / min

	// PM telemetry over the recent 60s window.
	PMRate         float64 // outbound user-PMs / min
	PMTargetCount  int     // distinct recipients in the window
	MentionRate    float64 // chan msgs that mention >=3 nicks / min
	NickServSpoofs int     // PMs whose body matches a NickServ phishing pattern
}

// Registry holds all installed rules.
type Registry struct {
	mu    sync.RWMutex
	rules []Rule
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(rule Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = append(r.rules, rule)
}

func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.rules))
	for i, r := range r.rules {
		out[i] = r.Name()
	}
	return out
}

// Dispatch runs every registered rule against the event and returns
// all alerts that fired.
func (r *Registry) Dispatch(u UserSnapshot, ev *events.Event) []Alert {
	r.mu.RLock()
	rules := r.rules
	r.mu.RUnlock()
	var out []Alert
	for _, rule := range rules {
		out = append(out, rule.Observe(u, ev)...)
	}
	return out
}

// --- Concrete rules ----------------------------------------------------

// floodRule: messages-per-minute over a threshold.
type floodRule struct {
	threshold float64 // messages per minute
}

func (f floodRule) Name() string { return "flood" }
func (f floodRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventChanMsg && ev.Kind != events.EventUserMsg {
		return nil
	}
	if u.RecentMsgRate < f.threshold {
		return nil
	}
	// Linear ramp: at threshold => 0.5, at 2x threshold => ~0.95.
	conf := 1.0 - (f.threshold / (u.RecentMsgRate + 1e-6))
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}
	return []Alert{{
		Kind:        "flood",
		UID:         u.UID,
		Nick:        u.Nick,
		Channel:     ev.Channel,
		Confidence:  conf,
		Evidence:    formatRate(u.RecentMsgRate, "messages/min"),
		At:          ev.At(),
		TriggeredBy: ev,
	}}
}

// repeatRule: duplicate-message hash count over a threshold.
type repeatRule struct {
	threshold int // distinct duplicate hits in recent window
}

func (r repeatRule) Name() string { return "repeat" }
func (r repeatRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventChanMsg && ev.Kind != events.EventUserMsg {
		return nil
	}
	if u.DupHashCount < r.threshold {
		return nil
	}
	conf := 1.0 - (float64(r.threshold) / float64(u.DupHashCount+1))
	if conf > 1 {
		conf = 1
	}
	return []Alert{{
		Kind:        "repeat",
		UID:         u.UID,
		Nick:        u.Nick,
		Channel:     ev.Channel,
		Confidence:  conf,
		Evidence:    formatInt(u.DupHashCount, "duplicate-hash hits in window"),
		At:          ev.At(),
		TriggeredBy: ev,
	}}
}

// massJoinRule: channel-joins-per-minute over a threshold.
type massJoinRule struct {
	threshold float64
}

func (m massJoinRule) Name() string { return "mass_join" }
func (m massJoinRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventJoin {
		return nil
	}
	if u.RecentJoinRate < m.threshold {
		return nil
	}
	conf := 1.0 - (m.threshold / (u.RecentJoinRate + 1e-6))
	if conf > 1 {
		conf = 1
	}
	return []Alert{{
		Kind:        "mass_join",
		UID:         u.UID,
		Nick:        u.Nick,
		Channel:     ev.Channel,
		Confidence:  conf,
		Evidence:    formatRate(u.RecentJoinRate, "joins/min"),
		At:          ev.At(),
		TriggeredBy: ev,
	}}
}

// linkSpamRule: URL in message AND user is new on network (under N
// seconds since connect) AND has not chatted before. Catches the
// classic "join channel, drop URL, leave".
type linkSpamRule struct {
	maxAgeOnNet time.Duration
}

func (l linkSpamRule) Name() string { return "link_spam" }
func (l linkSpamRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventChanMsg {
		return nil
	}
	if u.URLCount == 0 {
		return nil
	}
	age := ev.At().Sub(u.FirstSeen)
	if age > l.maxAgeOnNet {
		return nil
	}
	if u.MsgCount > 3 {
		// They've actually been chatting -- not a drop-and-go.
		return nil
	}
	// Brand new + URL = high confidence; older + URL ramps down.
	conf := 1.0 - (age.Seconds() / l.maxAgeOnNet.Seconds())
	return []Alert{{
		Kind:        "link_spam",
		UID:         u.UID,
		Nick:        u.Nick,
		Channel:     ev.Channel,
		Confidence:  conf,
		Evidence:    "URL posted within " + age.Round(time.Second).String() + " of connect",
		At:          ev.At(),
		TriggeredBy: ev,
	}}
}

// idleBurstRule: user has been on the network for > N minutes, then
// suddenly produces > M messages in the last minute.
type idleBurstRule struct {
	minAge       time.Duration
	burstPerMin  float64
	idleBefore   time.Duration // how long they were idle before the burst
}

func (i idleBurstRule) Name() string { return "idle_burst" }
func (i idleBurstRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventChanMsg && ev.Kind != events.EventUserMsg {
		return nil
	}
	age := ev.At().Sub(u.FirstSeen)
	if age < i.minAge {
		return nil
	}
	if u.RecentMsgRate < i.burstPerMin {
		return nil
	}
	// The user must be in a burst that started AFTER a long silence.
	// BurstStartIdleGap is set by the state layer when a message
	// arrives following >= burstResumeThreshold of inactivity, and
	// stays set until the burst itself ends -- so the rule sees a
	// stable "you came back from idle and are still going" signal
	// even on the 12th burst message.
	if u.BurstStartIdleGap < i.idleBefore {
		return nil
	}
	conf := u.RecentMsgRate / (u.RecentMsgRate + i.burstPerMin)
	return []Alert{{
		Kind:        "idle_burst",
		UID:         u.UID,
		Nick:        u.Nick,
		Channel:     ev.Channel,
		Confidence:  conf,
		Evidence:    formatRate(u.RecentMsgRate, "messages/min after extended idle"),
		At:          ev.At(),
		TriggeredBy: ev,
	}}
}

// ctcpStormRule: CTCP requests/min over threshold.
type ctcpStormRule struct {
	threshold int
}

func (c ctcpStormRule) Name() string { return "ctcp_storm" }
func (c ctcpStormRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventCTCP {
		return nil
	}
	if u.CTCPCount < c.threshold {
		return nil
	}
	conf := float64(u.CTCPCount) / float64(u.CTCPCount+c.threshold)
	return []Alert{{
		Kind:        "ctcp_storm",
		UID:         u.UID,
		Nick:        u.Nick,
		Channel:     ev.Channel,
		Confidence:  conf,
		Evidence:    formatInt(u.CTCPCount, "CTCP requests"),
		At:          ev.At(),
		TriggeredBy: ev,
	}}
}

// shoutingRule: high uppercase ratio sustained over several messages.
// Catches caps-lock-only chat that often correlates with abuse.
type shoutingRule struct {
	minMessages     int
	upperThreshold  float64 // [0, 1]
}

func (s shoutingRule) Name() string { return "shouting" }
func (s shoutingRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventChanMsg {
		return nil
	}
	if u.MsgCount < s.minMessages {
		return nil
	}
	if u.UpperRatioMean < s.upperThreshold {
		return nil
	}
	conf := (u.UpperRatioMean - s.upperThreshold) / (1.0 - s.upperThreshold + 1e-6)
	return []Alert{{
		Kind:        "shouting",
		UID:         u.UID,
		Nick:        u.Nick,
		Channel:     ev.Channel,
		Confidence:  conf,
		Evidence:    "sustained uppercase ratio " + formatPct(u.UpperRatioMean),
		At:          ev.At(),
		TriggeredBy: ev,
	}}
}

// DefaultRegistry returns a registry preloaded with the built-in
// rules and tuned default thresholds. Tweak the thresholds before
// production: training against the sim env will calibrate them.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(floodRule{threshold: 30})            // >30 msg/min
	r.Register(repeatRule{threshold: 4})            // 4+ duplicate hits in window
	r.Register(massJoinRule{threshold: 10})         // >10 joins/min
	r.Register(linkSpamRule{maxAgeOnNet: 30 * time.Second})
	r.Register(idleBurstRule{
		minAge:      10 * time.Minute,
		burstPerMin: 10,
		idleBefore:  5 * time.Minute,
	})
	r.Register(ctcpStormRule{threshold: 6})
	r.Register(shoutingRule{minMessages: 4, upperThreshold: 0.85})
	r.Register(nickFlipRule{threshold: 5})  // >5 nick changes/min
	r.Register(hopFloodRule{threshold: 8})  // >8 join+part/min
	r.Register(pmFloodRule{threshold: 12})  // >12 PMs/min outbound
	r.Register(pmShotgunRule{threshold: 5}) // >=5 distinct PM targets in window
	r.Register(mentionStormRule{threshold: 3}) // >=3 mention-bomb msgs/min
	r.Register(nickServSpoofRule{})
	return r
}

// pmFloodRule: outbound PM rate above threshold.
type pmFloodRule struct{ threshold float64 }

func (p pmFloodRule) Name() string { return "pm_flood" }
func (p pmFloodRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventUserMsg {
		return nil
	}
	if u.PMRate < p.threshold {
		return nil
	}
	conf := 1.0 - (p.threshold / (u.PMRate + 1e-6))
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}
	return []Alert{{
		Kind: "pm_flood", UID: u.UID, Nick: u.Nick,
		Confidence: conf,
		Evidence:   formatRate(u.PMRate, "PMs/min outbound"),
		At:         ev.At(), TriggeredBy: ev,
	}}
}

// pmShotgunRule: one sender PMing many distinct targets in a window.
// Spambot / harassment pattern.
type pmShotgunRule struct{ threshold int }

func (p pmShotgunRule) Name() string { return "pm_shotgun" }
func (p pmShotgunRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventUserMsg {
		return nil
	}
	if u.PMTargetCount < p.threshold {
		return nil
	}
	conf := float64(u.PMTargetCount-p.threshold) / float64(u.PMTargetCount+1)
	if conf < 0.3 {
		conf = 0.3
	}
	return []Alert{{
		Kind: "pm_shotgun", UID: u.UID, Nick: u.Nick,
		Confidence: conf,
		Evidence:   formatInt(u.PMTargetCount, "distinct PM targets in 60s"),
		At:         ev.At(), TriggeredBy: ev,
	}}
}

// mentionStormRule: chan msgs that tag many users at once -- common
// harassment / pile-on pattern.
type mentionStormRule struct{ threshold float64 }

func (m mentionStormRule) Name() string { return "mention_storm" }
func (m mentionStormRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventChanMsg {
		return nil
	}
	if u.MentionRate < m.threshold {
		return nil
	}
	conf := 1.0 - (m.threshold / (u.MentionRate + 1e-6))
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}
	return []Alert{{
		Kind: "mention_storm", UID: u.UID, Nick: u.Nick, Channel: ev.Channel,
		Confidence: conf,
		Evidence:   formatRate(u.MentionRate, "mention-bomb msgs/min"),
		At:         ev.At(), TriggeredBy: ev,
	}}
}

// nickServSpoofRule: detected NickServ phishing language in a PM.
type nickServSpoofRule struct{}

func (n nickServSpoofRule) Name() string { return "nickserv_spoof" }
func (n nickServSpoofRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventUserMsg {
		return nil
	}
	if u.NickServSpoofs < 1 {
		return nil
	}
	conf := 0.7 + 0.05*float64(u.NickServSpoofs)
	if conf > 1 {
		conf = 1
	}
	return []Alert{{
		Kind: "nickserv_spoof", UID: u.UID, Nick: u.Nick,
		Confidence: conf,
		Evidence:   formatInt(u.NickServSpoofs, "NickServ-phishing PM(s)"),
		At:         ev.At(), TriggeredBy: ev,
	}}
}

// nickFlipRule: rapid nick changes -- common evasion / impersonation.
type nickFlipRule struct{ threshold float64 }

func (n nickFlipRule) Name() string { return "nick_flip" }
func (n nickFlipRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventNick {
		return nil
	}
	if u.NickFlipRate < n.threshold {
		return nil
	}
	conf := 1.0 - (n.threshold / (u.NickFlipRate + 1e-6))
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}
	return []Alert{{
		Kind: "nick_flip", UID: u.UID, Nick: u.Nick,
		Confidence: conf,
		Evidence:   formatRate(u.NickFlipRate, "nick changes/min"),
		At:         ev.At(), TriggeredBy: ev,
	}}
}

// hopFloodRule: rapid join+part cycling. Botnets often hop channels.
type hopFloodRule struct{ threshold float64 }

func (h hopFloodRule) Name() string { return "hop_flood" }
func (h hopFloodRule) Observe(u UserSnapshot, ev *events.Event) []Alert {
	if ev.Kind != events.EventJoin && ev.Kind != events.EventPart {
		return nil
	}
	if u.HopRate < h.threshold {
		return nil
	}
	conf := 1.0 - (h.threshold / (u.HopRate + 1e-6))
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}
	return []Alert{{
		Kind: "hop_flood", UID: u.UID, Nick: u.Nick, Channel: ev.Channel,
		Confidence: conf,
		Evidence:   formatRate(u.HopRate, "joins+parts/min"),
		At:         ev.At(), TriggeredBy: ev,
	}}
}

// --- formatting helpers (avoid pulling fmt into the hot path twice) -

func formatInt(n int, unit string) string {
	return intToStr(n) + " " + unit
}

func formatRate(rate float64, unit string) string {
	return floatToStr(rate, 1) + " " + unit
}

func formatPct(ratio float64) string {
	return floatToStr(ratio*100, 0) + "%"
}

func intToStr(n int) string {
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

func floatToStr(f float64, dp int) string {
	// Simple non-allocating-ish float format for log strings.
	whole := int(f)
	s := intToStr(whole)
	if dp <= 0 {
		return s
	}
	frac := f - float64(whole)
	if frac < 0 {
		frac = -frac
	}
	mul := 1
	for i := 0; i < dp; i++ {
		mul *= 10
	}
	fracPart := int(frac*float64(mul) + 0.5)
	return s + "." + strings.Repeat("0", dp-len(intToStr(fracPart))) + intToStr(fracPart)
}

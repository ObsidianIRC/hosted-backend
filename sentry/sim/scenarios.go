// Package sim is the local-only training and test harness for sentry.
// It synthesizes Event streams that mirror what obbyircd's sentinel.c
// would emit under various IRC behaviours, then feeds them through
// the sentry pipeline. Every scenario carries an expected-label so
// the framework can score detection accuracy.
//
// Two delivery modes are supported:
//
//   - Deterministic mode (this file): pure Go event generation. Fast
//     (millions of synthetic events/sec), reproducible by seed, used
//     in unit tests and during L3 training.
//   - Real-IRC mode (sim/harness.go, next slice): spin up a private
//     obbyircd on localhost with a throwaway config + ephemeral state,
//     drive it with bot clients, let sentinel.c emit through the live
//     socket. Slower but proves the C hooks fire correctly.
//
// Nothing in either mode reaches the network. All traffic stays on
// loopback or in-process.
package sim

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"backend/sentry/events"
)

// Label tags a scenario as benign or as a specific malicious pattern.
// The set must stay aligned with sentry/heuristics rule names so the
// scoring pass can match alerts to expected detections.
type Label string

const (
	LabelBenign     Label = "benign"
	LabelFlood      Label = "flood"
	LabelRepeat     Label = "repeat"
	LabelMassJoin   Label = "mass_join"
	LabelLinkSpam   Label = "link_spam"
	LabelIdleBurst  Label = "idle_burst"
	LabelCTCPStorm  Label = "ctcp_storm"
	LabelShouting   Label = "shouting"
	LabelNickFlip   Label = "nick_flip"
	LabelHopFlood   Label = "hop_flood"
)

// Scenario emits a sequence of events for ONE synthetic user, plus
// the label the detection pipeline ought to attach.
type Scenario struct {
	Name        string // descriptive identifier
	Label       Label  // expected detection (or LabelBenign)
	NickPrefix  string // e.g. "spammer"; the harness appends a digit
	Description string

	// Generate produces the event stream for one instance of this
	// scenario. rng is the per-instance RNG seeded by the harness.
	// startAt is the synthetic wall-clock anchor; subsequent event
	// timestamps are offsets from it.
	Generate func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event
}

// --- Helpers -----------------------------------------------------------

func ev(kind events.EventKind, uid, nick string, at time.Time, fn func(*events.Event)) *events.Event {
	e := &events.Event{Kind: kind, UID: uid, Nick: nick, Time: at.UnixMilli()}
	if fn != nil {
		fn(e)
	}
	return e
}

// connectAndRegister is the canonical opening pair every scenario
// uses so feature extraction has the right FirstSeen anchor.
func connectAndRegister(uid, nick string, at time.Time, account string, tls bool) []*events.Event {
	c := ev(events.EventConnect, uid, nick, at, func(e *events.Event) {
		e.Ident = "u" + uid
		e.Host = nick + ".sim.local"
		e.IP = "127.0.0.1"
		e.Account = account
		e.IsTLS = tls
	})
	r := ev(events.EventRegister, uid, nick, at.Add(50*time.Millisecond), func(e *events.Event) {
		e.Ident = "u" + uid
		e.Host = nick + ".sim.local"
		e.IP = "127.0.0.1"
		e.Account = account
		e.IsTLS = tls
	})
	return []*events.Event{c, r}
}

// --- Concrete scenarios ------------------------------------------------

// BenignChat: well-behaved user. Joins one channel, chats occasionally
// over a few minutes, parts cleanly. Must NOT trigger any rule.
var BenignChat = Scenario{
	Name:        "benign-chat",
	Label:       LabelBenign,
	NickPrefix:  "alice",
	Description: "ordinary user with sparse, varied messages",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, nick, true)
		ch := "#general"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(2*time.Second), func(e *events.Event) {
			e.Channel = ch
		}))
		corpus := []string{
			"morning everyone",
			"anyone seen the latest patch notes?",
			"that build worked great for me",
			"thanks for the heads up",
			"agreed, that's the cleaner solution",
			"i'll take a look at it tonight",
			"haha yeah, ran into that one too",
		}
		// Cycle the corpus so a benign user never trips the repeat
		// heuristic just because RNG happened to pick the same string
		// 4+ times.
		idx := rng.Intn(len(corpus))
		for i := 0; i < 8; i++ {
			gap := time.Duration(15+rng.Intn(45)) * time.Second
			at := startAt.Add(2*time.Second + gap*time.Duration(i+1))
			text := corpus[(idx+i)%len(corpus)]
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
				e.Text = text
			}))
		}
		end := startAt.Add(10 * time.Minute)
		evs = append(evs, ev(events.EventPart, uid, nick, end, func(e *events.Event) {
			e.Channel = ch
		}))
		evs = append(evs, ev(events.EventQuit, uid, nick, end.Add(time.Second), nil))
		return evs
	},
}

// SpamCorpus is a small library of plausible-looking but non-malicious
// spam strings. URLs use the .invalid TLD (reserved by RFC 2606 to be
// unresolvable) so even if leaked nothing real is targeted.
var SpamCorpus = []string{
	"FREE GIFT CARD claim now at https://win.invalid/promo",
	"Earn $5000/week working from home — DM me",
	"Your account has been compromised, verify at https://secure.invalid/login",
	"PS5 GIVEAWAY first 100 to react win one!!!",
	"crypto millionaire course only $99 today, normally $999",
	"Hot singles in your area waiting to chat right now",
	"ACT FAST: limited stock on the new iPhone, https://deal.invalid/buy",
	"Make money fast with this one simple trick they don't want you to know",
	"BREAKING: insider stock tip, +400% guaranteed by friday",
	"Get followers fast 1000 for $5 https://growfast.invalid/sub",
}

// PickSpam returns a varied spam string seeded by index. Variants
// include numbered tags so the repeat-detector still distinguishes
// them while the overall pattern stays spam-shaped.
func PickSpam(rng *rand.Rand, idx int) string {
	base := SpamCorpus[rng.Intn(len(SpamCorpus))]
	return base + " [#" + intToStrLocal(idx) + "]"
}

// PickChannel returns one of the broadcast-style channels an
// attacker would plausibly target. Bombard runs over many of them
// per session for realistic blast radius.
var SpamChannels = []string{"#general", "#chat", "#lobby", "#help", "#offtopic", "#trade", "#news"}

func RandomChannels(rng *rand.Rand, n int) []string {
	out := make([]string, 0, n)
	pool := append([]string{}, SpamChannels...)
	rng.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if n > len(pool) {
		n = len(pool)
	}
	for i := 0; i < n; i++ {
		out = append(out, pool[i])
	}
	return out
}

// FloodSpammer: ~80 messages in 60 seconds across multiple channels.
// Must trigger "flood".
var FloodSpammer = Scenario{
	Name:        "flood-spammer",
	Label:       LabelFlood,
	NickPrefix:  "flood",
	Description: "rapid-fire varied spam across multiple channels",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		chans := RandomChannels(rng, 3+rng.Intn(3))
		for i, c := range chans {
			evs = append(evs, ev(events.EventJoin, uid, nick,
				startAt.Add(time.Duration(500+i*200)*time.Millisecond),
				func(e *events.Event) { e.Channel = c }))
		}
		for i := 0; i < 80; i++ {
			at := startAt.Add(time.Second + time.Duration(i*750)*time.Millisecond)
			ch := chans[i%len(chans)]
			text := PickSpam(rng, i)
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
				e.Text = text
			}))
		}
		return evs
	},
}

// RepeatSpammer: identical spam pasted into many channels. Must
// trigger "repeat".
var RepeatSpammer = Scenario{
	Name:        "repeat-spammer",
	Label:       LabelRepeat,
	NickPrefix:  "echo",
	Description: "identical spam line copy-pasted across channels",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		chans := RandomChannels(rng, 4)
		for i, c := range chans {
			evs = append(evs, ev(events.EventJoin, uid, nick,
				startAt.Add(time.Duration(500+i*200)*time.Millisecond),
				func(e *events.Event) { e.Channel = c }))
		}
		text := SpamCorpus[rng.Intn(len(SpamCorpus))]
		for i := 0; i < 12; i++ {
			at := startAt.Add(time.Second + time.Duration(i*2500)*time.Millisecond)
			ch := chans[i%len(chans)]
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
				e.Text = text
			}))
		}
		return evs
	},
}

// MassJoiner: joins 20 channels in 30 seconds. Must trigger
// "mass_join".
var MassJoiner = Scenario{
	Name:        "mass-joiner",
	Label:       LabelMassJoin,
	NickPrefix:  "joinbot",
	Description: "client joining channels far faster than humans do",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		for i := 0; i < 20; i++ {
			at := startAt.Add(time.Second + time.Duration(i*1500)*time.Millisecond)
			ch := fmt.Sprintf("#chan%d", i)
			evs = append(evs, ev(events.EventJoin, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
			}))
		}
		return evs
	},
}

// LinkDropper: brand-new client joins, drops a URL in EVERY channel
// it can reach, then quits. Must trigger "link_spam".
var LinkDropper = Scenario{
	Name:        "link-dropper",
	Label:       LabelLinkSpam,
	NickPrefix:  "driveby",
	Description: "fresh connect + URL pasted into every channel + quit",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		chans := RandomChannels(rng, 5)
		for i, c := range chans {
			joinAt := startAt.Add(2*time.Second + time.Duration(i*400)*time.Millisecond)
			evs = append(evs, ev(events.EventJoin, uid, nick, joinAt, func(e *events.Event) { e.Channel = c }))
			evs = append(evs, ev(events.EventChanMsg, uid, nick, joinAt.Add(700*time.Millisecond), func(e *events.Event) {
				e.Channel = c
				e.Text = PickSpam(rng, i)
			}))
		}
		evs = append(evs, ev(events.EventQuit, uid, nick, startAt.Add(15*time.Second), nil))
		return evs
	},
}

// CTCPFloodBot: hammers CTCP requests. Must trigger "ctcp_storm".
var CTCPFloodBot = Scenario{
	Name:        "ctcp-flood",
	Label:       LabelCTCPStorm,
	NickPrefix:  "ctcpbot",
	Description: "rapid CTCP requests against the room",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		ch := "#general"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second), func(e *events.Event) {
			e.Channel = ch
		}))
		for i := 0; i < 10; i++ {
			at := startAt.Add(time.Second + time.Duration(i*500)*time.Millisecond)
			evs = append(evs, ev(events.EventCTCP, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
				e.Text = "\x01VERSION\x01"
			}))
		}
		return evs
	},
}

// Shouter: a stream of all-caps messages. Must trigger "shouting".
var Shouter = Scenario{
	Name:        "shouter",
	Label:       LabelShouting,
	NickPrefix:  "yeller",
	Description: "sustained ALL-CAPS chatter",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		ch := "#general"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second), func(e *events.Event) {
			e.Channel = ch
		}))
		corpus := []string{
			"THIS IS COMPLETELY UNACCEPTABLE",
			"WHY IS NOBODY ANSWERING",
			"I HAVE BEEN WAITING FOR HOURS",
			"PLEASE READ THE MESSAGE",
			"THIS IS A FORMAL COMPLAINT",
			"YOU PEOPLE ARE THE WORST",
		}
		for i := 0; i < 6; i++ {
			at := startAt.Add(time.Second + time.Duration(i*10)*time.Second)
			text := corpus[i%len(corpus)]
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
				e.Text = text
			}))
		}
		return evs
	},
}

// IdleBurst: connects, sits silent for 15 minutes, then erupts.
// Must trigger "idle_burst".
var IdleBurst = Scenario{
	Name:        "idle-burst",
	Label:       LabelIdleBurst,
	NickPrefix:  "lurker",
	Description: "long lurk followed by a sudden 30-msg eruption",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		ch := "#general"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(2*time.Second), func(e *events.Event) {
			e.Channel = ch
		}))
		// One innocuous message right after join so LastMsg gets set.
		evs = append(evs, ev(events.EventChanMsg, uid, nick, startAt.Add(5*time.Second), func(e *events.Event) {
			e.Channel = ch
			e.Text = "hi everyone"
		}))
		// Long idle, then a moderate eruption. Burst rate must be
		// above idle_burst's 10/min threshold but below flood's
		// 30/min, otherwise flood masks the more specific label.
		// 4s gap = 15/min, comfortably in that sweet spot.
		burstAt := startAt.Add(20 * time.Minute)
		for i := 0; i < 15; i++ {
			at := burstAt.Add(time.Duration(i*4) * time.Second)
			text := fmt.Sprintf("burst msg %d -- %s", i, strings.Repeat("x", rng.Intn(20)+5))
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
				e.Text = text
			}))
		}
		return evs
	},
}

// NickFlipper: rapid nick changes -- impersonation / evasion.
var NickFlipper = Scenario{
	Name:        "nick-flipper",
	Label:       "nick_flip",
	NickPrefix:  "flip",
	Description: "user rapidly cycles through nicks",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		ch := "#general"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second), func(e *events.Event) {
			e.Channel = ch
		}))
		for i := 0; i < 8; i++ {
			at := startAt.Add(time.Second + time.Duration(i*4)*time.Second)
			newNick := nick + "_" + intToStrLocal(i)
			evs = append(evs, ev(events.EventNick, uid, newNick, at, nil))
		}
		return evs
	},
}

// HopFlooder: rapid join/part cycling on multiple channels.
var HopFlooder = Scenario{
	Name:        "hop-flooder",
	Label:       "hop_flood",
	NickPrefix:  "hop",
	Description: "client cycling join/part across channels",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		for i := 0; i < 8; i++ {
			ch := "#c" + intToStrLocal(i%3)
			at := startAt.Add(time.Second + time.Duration(i*3)*time.Second)
			evs = append(evs, ev(events.EventJoin, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
			}))
			evs = append(evs, ev(events.EventPart, uid, nick, at.Add(2*time.Second), func(e *events.Event) {
				e.Channel = ch
			}))
		}
		return evs
	},
}

// SlowBurnSpammer: drops a URL every couple minutes. Doesn't trip
// rate-based heuristics on its own but L3 should still learn the
// pattern via URL count + freshly connected + low msg count features.
var SlowBurnSpammer = Scenario{
	Name:        "slow-burn-spammer",
	Label:       "link_spam",
	NickPrefix:  "slow",
	Description: "low-rate URL drops over hours",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		ch := "#general"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(2*time.Second), func(e *events.Event) {
			e.Channel = ch
		}))
		// 1 URL message every ~3 minutes for an hour.
		for i := 0; i < 20; i++ {
			at := startAt.Add(time.Duration(20+i*180) * time.Second)
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
				e.Text = "check this out https://promo-" + intToStrLocal(i) + ".example/click"
			}))
		}
		return evs
	},
}

// --- Adversarial evaders -------------------------------------------
// These scenarios try to slip past the L1 thresholds: low rates, no
// duplicates, mixed timing. The L3 classifier should still flag them
// from the combination of features, even when no single L1 rule fires.

// SubThresholdSpammer: sits just under the flood rate (25/min) and
// posts URLs every few messages. No single L1 rule trips; L3 must
// learn the joint pattern.
var SubThresholdSpammer = Scenario{
	Name: "subthreshold-spammer", Label: LabelLinkSpam, NickPrefix: "evade",
	Description: "spam just under L1 rate threshold; URL drips",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		ch := "#general"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second), func(e *events.Event) { e.Channel = ch }))
		for i := 0; i < 40; i++ {
			at := startAt.Add(time.Second + time.Duration(i)*2400*time.Millisecond) // 25/min
			text := "interesting "
			if i%3 == 0 {
				text = "check out https://promo-" + intToStrLocal(i) + ".biz/visit"
			}
			text += intToStrLocal(i)
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) { e.Channel = ch; e.Text = text }))
		}
		return evs
	},
}

// MixedAttacker: blends mild patterns from several attack families.
// Each signal alone is sub-threshold; together they should expose
// the user as malicious to L3.
var MixedAttacker = Scenario{
	Name: "mixed-attacker", Label: LabelFlood, NickPrefix: "mixed",
	Description: "mild spam + mild CTCP + mild hop, none on its own enough",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "", false)
		ch1, ch2 := "#general", "#help"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second), func(e *events.Event) { e.Channel = ch1 }))
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(3*time.Second), func(e *events.Event) { e.Channel = ch2 }))
		// 20 msgs/min with intermittent URLs (sub-flood, sub-link-spam).
		for i := 0; i < 25; i++ {
			at := startAt.Add(time.Second + time.Duration(i)*3*time.Second)
			text := "msg variant " + intToStrLocal(i)
			if i%5 == 0 {
				text = "see https://deals" + intToStrLocal(i) + ".example/get"
			}
			channel := ch1
			if i%2 == 0 {
				channel = ch2
			}
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) { e.Channel = channel; e.Text = text }))
		}
		// A few CTCP requests sprinkled in (sub-ctcp_storm).
		for i := 0; i < 4; i++ {
			at := startAt.Add(time.Duration(15+i*8) * time.Second)
			evs = append(evs, ev(events.EventCTCP, uid, nick, at, func(e *events.Event) { e.Channel = ch1; e.Text = "\x01VERSION\x01" }))
		}
		return evs
	},
}

// --- Additional benign patterns ------------------------------------

// LurkBenign: connects, joins, says nothing for an hour. Common
// pattern; classifier must not treat silence as suspicious.
var LurkBenign = Scenario{
	Name: "lurk-benign", Label: LabelBenign, NickPrefix: "lurk",
	Description: "joins and reads silently",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, nick, true)
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(2*time.Second), func(e *events.Event) { e.Channel = "#general" }))
		evs = append(evs, ev(events.EventPart, uid, nick, startAt.Add(time.Hour), func(e *events.Event) { e.Channel = "#general" }))
		return evs
	},
}

// HelpdeskBot: posts a one-line greeting every ~5 minutes for an
// hour. Bot-like cadence but benign. Tests whether the classifier
// will false-positive automated friendly traffic.
var HelpdeskBot = Scenario{
	Name: "helpdesk-bot", Label: LabelBenign, NickPrefix: "helpbot",
	Description: "scripted welcome message every 5 minutes",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, "helpdesk", true)
		ch := "#welcome"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second), func(e *events.Event) { e.Channel = ch }))
		greetings := []string{
			"Welcome! Type !help for the command list.",
			"Quick tip: try !faq for common questions.",
			"Heads up: tickets via !ticket open <subject>.",
			"Office hours today: 09:00 to 17:00 UTC.",
			"To talk to a human, type !human.",
			"Reminder: search before asking, use !search.",
		}
		for i := 0; i < 10; i++ {
			at := startAt.Add(2*time.Second + time.Duration(i*300)*time.Second)
			// Append per-message uptime so each broadcast is unique
			// text -- real helpdesk bots include timestamps/IDs too.
			text := greetings[i%len(greetings)] + " [#" + intToStrLocal(i+1) + "]"
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) { e.Channel = ch; e.Text = text }))
		}
		return evs
	},
}

// MultiChannelBenign: chats in 3 channels at sustained but human rate.
var MultiChannelBenign = Scenario{
	Name: "multichan-benign", Label: LabelBenign, NickPrefix: "multi",
	Description: "active user across multiple channels at human rate",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, nick, true)
		chans := []string{"#general", "#dev", "#random"}
		// Space joins 30s apart -- realistic when a human is setting
		// up their session, well below mass_join threshold.
		for i, ch := range chans {
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Duration(2+i*30)*time.Second), func(e *events.Event) { e.Channel = ch }))
		}
		corpus := []string{
			"yeah that makes sense",
			"i'll grab lunch and look at it after",
			"oh nice, didn't realise that was merged",
			"thanks, that helped a lot",
			"let me know if you need a second pair of eyes",
			"the dashboard is loading slower than usual today",
			"agreed, +1 from me on the new approach",
			"i pushed a draft, comments welcome",
			"my dog is being adorable, brb taking a photo",
			"that explains the weird behaviour i saw earlier",
		}
		idx := rng.Intn(len(corpus))
		// 9 messages -- below 10 corpus items so we never cycle.
		for i := 0; i < 9; i++ {
			ch := chans[i%len(chans)]
			at := startAt.Add(5*time.Second + time.Duration(i*30)*time.Second)
			text := corpus[(idx+i)%len(corpus)]
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) { e.Channel = ch; e.Text = text }))
		}
		return evs
	},
}

// AllScenarios is the canonical set; the harness iterates this to
// score detection coverage.
var AllScenarios = []Scenario{
	BenignChat,
	FloodSpammer,
	RepeatSpammer,
	MassJoiner,
	LinkDropper,
	CTCPFloodBot,
	Shouter,
	IdleBurst,
	NickFlipper,
	HopFlooder,
	SlowBurnSpammer,
	LurkBenign,
	HelpdeskBot,
	MultiChannelBenign,
}

// AdversarialScenarios are evaders -- they're INTENTIONALLY held out
// of AllScenarios so the model is never directly trained on these
// exact patterns. Used for held-out evaluation: a strong model
// should still flag them based on the joint feature distribution
// learned from the canonical attacks.
var AdversarialScenarios = []Scenario{
	SubThresholdSpammer,
	MixedAttacker,
}

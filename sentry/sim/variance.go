// Procedural generators for sustained-bombardment training. Every
// session must produce a NEW shape of attack/benign behaviour so the
// classifier learns the underlying feature distributions instead of
// memorising a small template set.
package sim

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"backend/sentry/events"
)

// --- Procedural text -------------------------------------------------

// vocabSpam / vocabFiller / vocabBenign are large word pools the
// generator stitches together. They overlap on common English so a
// benign sentence and a spam sentence share vocabulary -- only the
// shape (urls, all-caps bursts, hype words, length distribution)
// differs, which is what we want the model to learn.
var (
	vocabHype = []string{"FREE", "URGENT", "ACT NOW", "LIMITED", "EXCLUSIVE", "GUARANTEED",
		"VERIFIED", "OFFICIAL", "WIN", "CLAIM", "BONUS", "SECRET", "BREAKING", "WARNING",
		"ALERT", "INSTANT", "MASSIVE", "INSANE", "PROVEN", "SHOCKING"}
	vocabSpamNouns = []string{"gift card", "bitcoin", "crypto", "investment", "course",
		"giveaway", "iphone", "ps5", "followers", "cash", "rewards", "subscription",
		"job", "income", "discount", "voucher", "trial", "membership", "credit", "deal",
		"loan", "casino", "spin", "jackpot", "prize", "ticket", "drop", "airdrop", "wallet"}
	vocabBenign = []string{"that", "this", "yeah", "ok", "agreed", "lol", "hmm", "right",
		"cool", "sure", "true", "fair", "nice", "thanks", "ping", "later", "morning",
		"evening", "today", "tomorrow", "actually", "interesting", "neat", "fine",
		"working on", "looking into", "reading", "testing", "deploying", "fixing",
		"running", "merging", "pushing", "drafting", "reviewing", "thinking"}
	vocabSubjects = []string{"i", "we", "they", "she", "he", "it", "anyone", "someone",
		"my team", "the docs", "the patch", "the build", "the ci"}
	vocabVerbs = []string{"saw", "tried", "wrote", "broke", "fixed", "merged",
		"deployed", "tested", "noticed", "wondered", "asked", "answered", "watched"}
	vocabTLDs    = []string{"invalid", "example", "test", "localhost"}
	vocabDomains = []string{"win", "promo", "deal", "shop", "buy", "claim", "free",
		"crypto", "earn", "secure", "verify", "rewards", "airdrop", "drop", "club",
		"vault", "bonus", "premium", "vip"}
	vocabPaths = []string{"click", "go", "sub", "join", "ref", "claim", "verify",
		"signup", "track", "promo", "offer", "win", "deal"}
)

// procSpamLine builds one spam-shaped string with high variance:
// random hype words, random products, optional URL, optional ALLCAPS,
// optional emoji-flavour punctuation, optional !!!!!! tail. Per-call
// uniqueness comes from a salt token so the repeat detector still
// distinguishes calls.
func procSpamLine(rng *rand.Rand, salt int) string {
	var b strings.Builder
	hypeCount := 1 + rng.Intn(3)
	for i := 0; i < hypeCount; i++ {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(vocabHype[rng.Intn(len(vocabHype))])
	}
	b.WriteString(" ")
	b.WriteString(vocabSpamNouns[rng.Intn(len(vocabSpamNouns))])
	if rng.Float64() < 0.7 {
		b.WriteString(" ")
		b.WriteString(procURL(rng))
	}
	if rng.Float64() < 0.4 {
		bangs := strings.Repeat("!", 1+rng.Intn(5))
		b.WriteString(bangs)
	}
	if rng.Float64() < 0.5 {
		// salty tail keeps each line distinct so RepeatRule only fires
		// when the bombard actually wants it to.
		b.WriteString(fmt.Sprintf(" [%d]", salt))
	}
	out := b.String()
	// Random partial-uppercase rewrite: simulate the all-caps style.
	if rng.Float64() < 0.35 {
		return strings.ToUpper(out)
	}
	return out
}

// procBenignLine builds a varied benign-shaped utterance. Same word
// pool overlap as spam minus the hype/URL hooks. Lengths range from
// a one-word ack to several clauses so msg_len_mean/var doesn't
// collapse to a single distribution.
func procBenignLine(rng *rand.Rand) string {
	style := rng.Intn(4)
	switch style {
	case 0:
		// Short ack.
		return vocabBenign[rng.Intn(len(vocabBenign))]
	case 1:
		// Two-word fragment.
		return vocabBenign[rng.Intn(len(vocabBenign))] + " " + vocabBenign[rng.Intn(len(vocabBenign))]
	case 2:
		// Sentence-ish.
		return fmt.Sprintf("%s %s the %s",
			vocabSubjects[rng.Intn(len(vocabSubjects))],
			vocabVerbs[rng.Intn(len(vocabVerbs))],
			vocabBenign[rng.Intn(len(vocabBenign))])
	default:
		// Longer reflection.
		return fmt.Sprintf("%s %s but %s",
			vocabSubjects[rng.Intn(len(vocabSubjects))],
			vocabVerbs[rng.Intn(len(vocabVerbs))],
			procBenignLine(rng))
	}
}

func procURL(rng *rand.Rand) string {
	domain := vocabDomains[rng.Intn(len(vocabDomains))]
	tld := vocabTLDs[rng.Intn(len(vocabTLDs))]
	path := vocabPaths[rng.Intn(len(vocabPaths))]
	if rng.Float64() < 0.3 {
		return fmt.Sprintf("https://%s-%d.%s/%s",
			domain, rng.Intn(9999), tld, path)
	}
	if rng.Float64() < 0.5 {
		return fmt.Sprintf("https://%s.%s/%s?ref=%d",
			domain, tld, path, rng.Intn(99999))
	}
	return fmt.Sprintf("https://%s%s.%s/%s",
		domain, vocabPaths[rng.Intn(len(vocabPaths))], tld, path)
}

// --- Procedural scenarios -------------------------------------------

// ProcFlood builds a flood-style scenario with randomised:
//   - message count (40..160)
//   - rate (40..150 msg/min)
//   - channel count (1..6)
//   - text shape (procSpamLine -- different every msg)
//   - join cadence (jittered)
func ProcFlood(rng *rand.Rand) Scenario {
	msgCount := 40 + rng.Intn(120)
	gapMs := 400 + rng.Intn(1100) // 0.4..1.5s between msgs
	chanCount := 1 + rng.Intn(6)
	return Scenario{
		Name:        "proc-flood",
		Label:       LabelFlood,
		NickPrefix:  randomNickPrefix(rng, "flood"),
		Description: "procedurally-generated rapid-fire chat",
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", r.Float64() < 0.2)
			chans := RandomChannels(r, chanCount)
			for i, c := range chans {
				evs = append(evs, ev(events.EventJoin, uid, nick,
					startAt.Add(time.Duration(300+i*200+r.Intn(400))*time.Millisecond),
					func(e *events.Event) { e.Channel = c }))
			}
			for i := 0; i < msgCount; i++ {
				jitter := time.Duration(r.Intn(gapMs/3+1)) * time.Millisecond
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond + jitter)
				ch := chans[r.Intn(len(chans))]
				text := procSpamLine(r, i)
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProcRepeat builds a repeat scenario where one message is hammered
// but the exact message text differs per session. Counts and channels
// vary so the SHAPE varies even if the rule that should fire stays
// constant.
func ProcRepeat(rng *rand.Rand) Scenario {
	repeats := 6 + rng.Intn(20)
	gapMs := 1500 + rng.Intn(4500)
	chanCount := 1 + rng.Intn(5)
	return Scenario{
		Name:       "proc-repeat",
		Label:      LabelRepeat,
		NickPrefix: randomNickPrefix(rng, "echo"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			chans := RandomChannels(r, chanCount)
			for i, c := range chans {
				evs = append(evs, ev(events.EventJoin, uid, nick,
					startAt.Add(time.Duration(300+i*250)*time.Millisecond),
					func(e *events.Event) { e.Channel = c }))
			}
			text := procSpamLine(r, 0) // ONE line, no salt -> repeats are identical
			for i := 0; i < repeats; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				ch := chans[i%len(chans)]
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProcLinkSpam: random URL drops with random density and channel set.
func ProcLinkSpam(rng *rand.Rand) Scenario {
	hits := 3 + rng.Intn(20)
	chanCount := 1 + rng.Intn(7)
	return Scenario{
		Name:       "proc-link-spam",
		Label:      LabelLinkSpam,
		NickPrefix: randomNickPrefix(rng, "driveby"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			chans := RandomChannels(r, chanCount)
			for i, c := range chans {
				joinAt := startAt.Add(time.Duration(500+i*300+r.Intn(500))*time.Millisecond)
				evs = append(evs, ev(events.EventJoin, uid, nick, joinAt, func(e *events.Event) { e.Channel = c }))
				if i < hits {
					evs = append(evs, ev(events.EventChanMsg, uid, nick, joinAt.Add(time.Duration(300+r.Intn(2000))*time.Millisecond),
						func(e *events.Event) {
							e.Channel = c
							e.Text = procSpamLine(r, i)
						}))
				}
			}
			return evs
		},
	}
}

// ProcMassJoin varies the join count and rate.
func ProcMassJoin(rng *rand.Rand) Scenario {
	joins := 12 + rng.Intn(40)
	gapMs := 400 + rng.Intn(1800)
	return Scenario{
		Name:       "proc-mass-join",
		Label:      LabelMassJoin,
		NickPrefix: randomNickPrefix(rng, "joinbot"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			for i := 0; i < joins; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond +
					time.Duration(r.Intn(gapMs/2))*time.Millisecond)
				ch := fmt.Sprintf("#chan%d", r.Intn(40))
				evs = append(evs, ev(events.EventJoin, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
				}))
			}
			return evs
		},
	}
}

// ProcShouter: high-uppercase chat with varied length and rate.
func ProcShouter(rng *rand.Rand) Scenario {
	count := 4 + rng.Intn(20)
	gapMs := 2000 + rng.Intn(8000)
	return Scenario{
		Name:       "proc-shouter",
		Label:      LabelShouting,
		NickPrefix: randomNickPrefix(rng, "yeller"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			ch := "#" + vocabPaths[r.Intn(len(vocabPaths))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second),
				func(e *events.Event) { e.Channel = ch }))
			for i := 0; i < count; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				text := strings.ToUpper(procBenignLine(r) + " " + procBenignLine(r))
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProcCTCPStorm.
func ProcCTCPStorm(rng *rand.Rand) Scenario {
	count := 6 + rng.Intn(30)
	gapMs := 200 + rng.Intn(900)
	return Scenario{
		Name:       "proc-ctcp-storm",
		Label:      LabelCTCPStorm,
		NickPrefix: randomNickPrefix(rng, "ctcpbot"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			ch := SpamChannels[r.Intn(len(SpamChannels))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second),
				func(e *events.Event) { e.Channel = ch }))
			ctcps := []string{"VERSION", "PING 12345", "TIME", "CLIENTINFO", "USERINFO", "FINGER"}
			for i := 0; i < count; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				body := ctcps[r.Intn(len(ctcps))]
				evs = append(evs, ev(events.EventCTCP, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = "\x01" + body + "\x01"
				}))
			}
			return evs
		},
	}
}

// ProcIdleBurst: variable idle window then variable burst rate.
func ProcIdleBurst(rng *rand.Rand) Scenario {
	idle := time.Duration(10+rng.Intn(40)) * time.Minute
	burst := 8 + rng.Intn(40)
	burstGapMs := 1000 + rng.Intn(5000)
	return Scenario{
		Name:       "proc-idle-burst",
		Label:      LabelIdleBurst,
		NickPrefix: randomNickPrefix(rng, "lurker"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			ch := SpamChannels[r.Intn(len(SpamChannels))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(2*time.Second),
				func(e *events.Event) { e.Channel = ch }))
			evs = append(evs, ev(events.EventChanMsg, uid, nick, startAt.Add(5*time.Second),
				func(e *events.Event) {
					e.Channel = ch
					e.Text = procBenignLine(r)
				}))
			burstAt := startAt.Add(idle)
			for i := 0; i < burst; i++ {
				at := burstAt.Add(time.Duration(i*burstGapMs) * time.Millisecond)
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = procSpamLine(r, i)
				}))
			}
			return evs
		},
	}
}

// ProcNickFlip: variable count and rate.
func ProcNickFlip(rng *rand.Rand) Scenario {
	count := 4 + rng.Intn(16)
	gapMs := 1500 + rng.Intn(4000)
	return Scenario{
		Name:       "proc-nick-flip",
		Label:      LabelNickFlip,
		NickPrefix: randomNickPrefix(rng, "flip"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			ch := SpamChannels[r.Intn(len(SpamChannels))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second),
				func(e *events.Event) { e.Channel = ch }))
			cur := nick
			for i := 0; i < count; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				newNick := fmt.Sprintf("%s_%d_%d", randomNickPrefix(r, ""), r.Intn(9999), i)
				cur = newNick
				evs = append(evs, ev(events.EventNick, uid, newNick, at, nil))
			}
			_ = cur
			return evs
		},
	}
}

// ProcHopFlood: rapid join/part across many channels.
func ProcHopFlood(rng *rand.Rand) Scenario {
	cycles := 6 + rng.Intn(20)
	gapMs := 800 + rng.Intn(2500)
	return Scenario{
		Name:       "proc-hop-flood",
		Label:      LabelHopFlood,
		NickPrefix: randomNickPrefix(rng, "hop"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			for i := 0; i < cycles; i++ {
				ch := fmt.Sprintf("#%s%d", vocabPaths[r.Intn(len(vocabPaths))], r.Intn(40))
				at := startAt.Add(time.Duration(i*gapMs) * time.Millisecond)
				evs = append(evs, ev(events.EventJoin, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
				}))
				evs = append(evs, ev(events.EventPart, uid, nick, at.Add(time.Duration(500+r.Intn(2000))*time.Millisecond),
					func(e *events.Event) { e.Channel = ch }))
			}
			return evs
		},
	}
}

// ProcMixed combines partial signals -- under-threshold rate + a
// couple URLs + occasional CTCP. None of the L1 rules SHOULD fire
// alone; L3 is the layer that should catch it.
func ProcMixed(rng *rand.Rand) Scenario {
	msgCount := 15 + rng.Intn(30)
	gapMs := 2000 + rng.Intn(2000)
	return Scenario{
		Name:       "proc-mixed",
		Label:      LabelFlood, // closest canonical label
		NickPrefix: randomNickPrefix(rng, "mixed"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			chans := RandomChannels(r, 2+r.Intn(3))
			for i, c := range chans {
				evs = append(evs, ev(events.EventJoin, uid, nick,
					startAt.Add(time.Duration(500+i*300)*time.Millisecond),
					func(e *events.Event) { e.Channel = c }))
			}
			for i := 0; i < msgCount; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				ch := chans[i%len(chans)]
				var text string
				switch r.Intn(4) {
				case 0:
					text = procSpamLine(r, i)
				case 1:
					text = strings.ToUpper(procBenignLine(r))
				default:
					text = procBenignLine(r)
				}
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = text
				}))
			}
			// Occasional CTCP.
			for i := 0; i < 1+r.Intn(3); i++ {
				evs = append(evs, ev(events.EventCTCP, uid, nick,
					startAt.Add(time.Duration(5+r.Intn(20))*time.Second),
					func(e *events.Event) {
						e.Channel = chans[0]
						e.Text = "\x01VERSION\x01"
					}))
			}
			return evs
		},
	}
}

// --- Benign variants -------------------------------------------------

// ProcChatter: a benign user who chats at varying intensity. Same
// text generator as the spam shouter but without hype words / URLs.
func ProcChatter(rng *rand.Rand) Scenario {
	msgCount := 4 + rng.Intn(30)
	gapMs := 5000 + rng.Intn(45000)
	chanCount := 1 + rng.Intn(4)
	return Scenario{
		Name:       "proc-chatter",
		Label:      LabelBenign,
		NickPrefix: randomNickPrefix(rng, "user"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			account := ""
			if r.Float64() < 0.5 {
				account = nick
			}
			evs := connectAndRegister(uid, nick, startAt, account, r.Float64() < 0.7)
			chans := RandomChannels(r, chanCount)
			for i, c := range chans {
				evs = append(evs, ev(events.EventJoin, uid, nick,
					startAt.Add(time.Duration(2+i*15)*time.Second),
					func(e *events.Event) { e.Channel = c }))
			}
			for i := 0; i < msgCount; i++ {
				at := startAt.Add(time.Duration(20+i*gapMs/1000)*time.Second +
					time.Duration(r.Intn(gapMs))*time.Millisecond)
				ch := chans[r.Intn(len(chans))]
				text := procBenignLine(r)
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProcBenignFast: a benign user with a quick-discussion burst — high
// rate, no URLs, varied content. Important hard-case: rate alone
// shouldn't condemn them.
func ProcBenignFast(rng *rand.Rand) Scenario {
	msgCount := 15 + rng.Intn(20)
	gapMs := 1500 + rng.Intn(3000)
	return Scenario{
		Name:       "proc-benign-fast",
		Label:      LabelBenign,
		NickPrefix: randomNickPrefix(rng, "fast"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, nick, true)
			ch := "#" + vocabPaths[r.Intn(len(vocabPaths))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(2*time.Second),
				func(e *events.Event) { e.Channel = ch }))
			for i := 0; i < msgCount; i++ {
				at := startAt.Add(3*time.Second + time.Duration(i*gapMs)*time.Millisecond)
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = procBenignLine(r)
				}))
			}
			return evs
		},
	}
}

// ProcBenignBot: a scripted helpful bot. Same message every N minutes,
// no URLs, predictable. Must not trip rules.
func ProcBenignBot(rng *rand.Rand) Scenario {
	msgs := 3 + rng.Intn(10)
	gapMin := 2 + rng.Intn(8)
	return Scenario{
		Name:       "proc-benign-bot",
		Label:      LabelBenign,
		NickPrefix: randomNickPrefix(rng, "bot"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "bot", true)
			ch := "#welcome"
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second),
				func(e *events.Event) { e.Channel = ch }))
			banner := fmt.Sprintf("hello from %s, ask me about anything", nick)
			for i := 0; i < msgs; i++ {
				at := startAt.Add(time.Duration(i*gapMin) * time.Minute)
				text := banner + fmt.Sprintf(" (msg %d)", i)
				_ = r
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// --- Composer --------------------------------------------------------

// --- Targeted abuse scenarios ----------------------------------------

// ProcHarassment: one attacker hammers ONE target via channel
// @-mentions. High mention rate against one victim.
func ProcHarassment(rng *rand.Rand) Scenario {
	count := 8 + rng.Intn(25)
	gapMs := 1500 + rng.Intn(4000)
	victim := randomNickPrefix(rng, "victim") + fmt.Sprintf("%d", rng.Intn(999))
	insults := []string{
		"you again, log off already",
		"nobody likes you here",
		"go back to your other channel",
		"stop posting, you're embarrassing",
		"why are you still here",
		"this place was better before you",
		"get a life",
		"keep crying about it",
	}
	return Scenario{
		Name:       "proc-harassment",
		Label:      "mention_storm",
		NickPrefix: randomNickPrefix(rng, "troll"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			ch := SpamChannels[r.Intn(len(SpamChannels))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second),
				func(e *events.Event) { e.Channel = ch }))
			for i := 0; i < count; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				// Always tag the same victim; sometimes pile on with
				// extra @-tokens so MentionRate climbs.
				text := "@" + victim + " " + insults[r.Intn(len(insults))]
				if r.Float64() < 0.4 {
					text = text + " @" + randomNickPrefix(r, "bystander") +
						" @" + randomNickPrefix(r, "witness")
				}
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProcMentionBomb: one msg that pings many users at once.
func ProcMentionBomb(rng *rand.Rand) Scenario {
	bombs := 3 + rng.Intn(8)
	gapMs := 4000 + rng.Intn(12000)
	return Scenario{
		Name:       "proc-mention-bomb",
		Label:      "mention_storm",
		NickPrefix: randomNickPrefix(rng, "tagger"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			ch := SpamChannels[r.Intn(len(SpamChannels))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second),
				func(e *events.Event) { e.Channel = ch }))
			for i := 0; i < bombs; i++ {
				at := startAt.Add(2*time.Second + time.Duration(i*gapMs)*time.Millisecond)
				// Build a single msg that tags 5..20 random nicks.
				tagN := 5 + r.Intn(16)
				var b strings.Builder
				b.WriteString("hey ")
				for j := 0; j < tagN; j++ {
					b.WriteString("@")
					b.WriteString(randomNickPrefix(r, "u") + fmt.Sprintf("%d", r.Intn(9999)))
					b.WriteString(" ")
				}
				b.WriteString(procSpamLine(r, i))
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = b.String()
				}))
			}
			return evs
		},
	}
}

// ProcPMShotgun: a spambot DMing many distinct users in quick
// succession with spam content.
func ProcPMShotgun(rng *rand.Rand) Scenario {
	targets := 8 + rng.Intn(30)
	gapMs := 300 + rng.Intn(2000)
	return Scenario{
		Name:       "proc-pm-shotgun",
		Label:      "pm_shotgun",
		NickPrefix: randomNickPrefix(rng, "dmbot"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			for i := 0; i < targets; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				target := randomNickPrefix(r, "user") + fmt.Sprintf("%d", r.Intn(99999))
				text := procSpamLine(r, i)
				evs = append(evs, ev(events.EventUserMsg, uid, nick, at, func(e *events.Event) {
					e.TargetNick = target
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProcPMFlood: rapid PMs to a SINGLE target (harassment via DM).
func ProcPMFlood(rng *rand.Rand) Scenario {
	count := 15 + rng.Intn(40)
	gapMs := 300 + rng.Intn(1500)
	return Scenario{
		Name:       "proc-pm-flood",
		Label:      "pm_flood",
		NickPrefix: randomNickPrefix(rng, "stalker"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			target := randomNickPrefix(r, "victim") + fmt.Sprintf("%d", r.Intn(9999))
			tails := []string{
				"answer me", "why are you ignoring me", "respond",
				"i know you're online", "stop hiding", "we need to talk",
				"don't ignore me", "you can't just leave",
			}
			for i := 0; i < count; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				text := tails[r.Intn(len(tails))] + " " + fmt.Sprintf("(%d)", i)
				evs = append(evs, ev(events.EventUserMsg, uid, nick, at, func(e *events.Event) {
					e.TargetNick = target
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProcNickServPhish: PMs containing a fake authentication prompt
// engineered to trick a user into leaking their NickServ password.
func ProcNickServPhish(rng *rand.Rand) Scenario {
	count := 3 + rng.Intn(15)
	gapMs := 1000 + rng.Intn(4000)
	phishLines := []string{
		"SECURITY: your account has been compromised, please re-authenticate. Type /msg NickServ IDENTIFY <your password> to confirm your account",
		"[ObbyNet Staff] Verify your password to NickServ now: /msg NickServ identify yourpassword",
		"Hi, network admin here. We're rolling out a key rotation -- please /msg NickServ identify <pw> within 5 min or be disconnected",
		"You have been flagged for review. To clear this, type /msg NickServ IDENTIFY <password>",
	}
	return Scenario{
		Name:       "proc-nickserv-phish",
		Label:      "nickserv_spoof",
		NickPrefix: randomNickPrefix(rng, "support"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			for i := 0; i < count; i++ {
				at := startAt.Add(time.Second + time.Duration(i*gapMs)*time.Millisecond)
				target := randomNickPrefix(r, "user") + fmt.Sprintf("%d", r.Intn(9999))
				text := phishLines[r.Intn(len(phishLines))]
				evs = append(evs, ev(events.EventUserMsg, uid, nick, at, func(e *events.Event) {
					e.TargetNick = target
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProcImpersonator: connects with a nick that suffixes "_" or a digit
// to a plausible real nick, then sits quietly trying to confuse
// channel members. The classifier should learn that the SHAPE
// (suspicious nick pattern + low activity + low feature levels) is
// not, on its own, a strong signal -- which is correct. We label as
// benign so the model treats the nick pattern itself as neutral and
// only condemns when other features escalate. (This is a "tricky
// negative" case for robustness training.)
func ProcImpersonator(rng *rand.Rand) Scenario {
	suffixes := []string{"_", "__", "1", "01", "_official", "-staff"}
	bases := []string{"valware", "Sentry", "Orca", "admin", "moderator", "staff"}
	stem := bases[rng.Intn(len(bases))] + suffixes[rng.Intn(len(suffixes))]
	return Scenario{
		Name:       "proc-impersonator",
		Label:      LabelBenign, // ambiguous case: name alone isn't enough
		NickPrefix: stem,
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			ch := SpamChannels[r.Intn(len(SpamChannels))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(2*time.Second),
				func(e *events.Event) { e.Channel = ch }))
			evs = append(evs, ev(events.EventChanMsg, uid, nick, startAt.Add(30*time.Second),
				func(e *events.Event) { e.Channel = ch; e.Text = procBenignLine(r) }))
			return evs
		},
	}
}

// ProcSlowToxicity: rare, low-rate insults sprinkled into otherwise
// normal chat -- the hardest case. Doesn't trip rate-based rules.
// Tagged as attacker so L3 has SOME signal to learn from, but only
// once a critical mass accumulates.
func ProcSlowToxicity(rng *rand.Rand) Scenario {
	totalMsgs := 15 + rng.Intn(30)
	gapSec := 60 + rng.Intn(180)
	toxic := []string{
		"this place is full of losers",
		"shut up no one cares",
		"you're all clowns",
		"why is this channel still alive",
		"go back to twitter",
		"keep crying",
	}
	return Scenario{
		Name:       "proc-slow-tox",
		Label:      LabelFlood, // best-fit, rare signal expected from L3 alone
		NickPrefix: randomNickPrefix(rng, "edgelord"),
		Generate: func(uid, nick string, startAt time.Time, _ *rand.Rand) []*events.Event {
			r := rand.New(rand.NewSource(int64(uid[0]) ^ startAt.UnixNano()))
			evs := connectAndRegister(uid, nick, startAt, "", false)
			ch := SpamChannels[r.Intn(len(SpamChannels))]
			evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(time.Second),
				func(e *events.Event) { e.Channel = ch }))
			for i := 0; i < totalMsgs; i++ {
				at := startAt.Add(time.Duration(i*gapSec) * time.Second)
				var text string
				if r.Float64() < 0.35 {
					text = toxic[r.Intn(len(toxic))]
				} else {
					text = procBenignLine(r)
				}
				evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
					e.Channel = ch
					e.Text = text
				}))
			}
			return evs
		},
	}
}

// ProceduralAttacker returns one randomised attacker scenario per call.
// Distribution roughly matches what a moderator would see on a busy
// network: floods/spammers most common, idle-burst rarest.
func ProceduralAttacker(rng *rand.Rand) Scenario {
	r := rng.Float64()
	switch {
	case r < 0.16:
		return ProcFlood(rng)
	case r < 0.28:
		return ProcLinkSpam(rng)
	case r < 0.38:
		return ProcRepeat(rng)
	case r < 0.46:
		return ProcMassJoin(rng)
	case r < 0.54:
		return ProcHopFlood(rng)
	case r < 0.60:
		return ProcShouter(rng)
	case r < 0.64:
		return ProcCTCPStorm(rng)
	case r < 0.67:
		return ProcNickFlip(rng)
	case r < 0.72:
		return ProcMixed(rng)
	case r < 0.80:
		return ProcHarassment(rng)
	case r < 0.86:
		return ProcMentionBomb(rng)
	case r < 0.91:
		return ProcPMShotgun(rng)
	case r < 0.95:
		return ProcPMFlood(rng)
	case r < 0.98:
		return ProcNickServPhish(rng)
	default:
		return ProcSlowToxicity(rng)
	}
}

// ProceduralBenign returns one randomised benign scenario per call.
func ProceduralBenign(rng *rand.Rand) Scenario {
	r := rng.Float64()
	switch {
	case r < 0.5:
		return ProcChatter(rng)
	case r < 0.75:
		return ProcBenignFast(rng)
	case r < 0.90:
		return ProcBenignBot(rng)
	default:
		// Impersonator with otherwise benign behaviour -- hard
		// negative so the model doesn't condemn on nick shape alone.
		return ProcImpersonator(rng)
	}
}

// randomNickPrefix returns a varied nick stem. Used to widen the
// distribution so the model can't latch onto a specific prefix.
func randomNickPrefix(rng *rand.Rand, fallback string) string {
	pools := []string{
		"alex", "sam", "jordan", "casey", "morgan", "river",
		"taylor", "jamie", "robin", "drew", "kim", "li",
		"yuki", "ren", "ace", "rio", "luna", "atlas",
		"nova", "echo", "kai", "max", "neo", "rex",
	}
	if rng.Intn(3) == 0 && fallback != "" {
		return fallback
	}
	return pools[rng.Intn(len(pools))] + fmt.Sprintf("%d", rng.Intn(99))
}

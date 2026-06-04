package sim

import (
	"math/rand"
	"strings"
	"time"

	"backend/sentry/events"
)

// markovCorpus is a small but varied IRC-style corpus. We don't need
// a huge dataset -- the goal is to produce plausible benign chatter
// with the linguistic features (lengths, casing, vocabulary spread)
// that L1 rules rely on for negative signals. Deliberately includes
// short reactions, longer thoughts, and the occasional emoji-ish
// punctuation pattern.
var markovCorpus = []string{
	"morning everyone, anything interesting today?",
	"i finally got that build working last night",
	"haha yeah, that one always gets me",
	"agreed, the second approach is cleaner",
	"can someone double-check the failing test in user_routes?",
	"i pushed the fix, please pull and let me know",
	"the docs are at the usual place if anyone needs them",
	"that's a good catch, thanks for spotting it",
	"i'll be afk for an hour, ping me if anything urgent comes up",
	"the latest patch notes have a nice section on the new api",
	"my coffee finally kicked in, ready to ship",
	"i think we should revisit this after lunch",
	"the migration looks clean to me, +1",
	"oh interesting, i didn't know that worked",
	"yeah that's fair, let me think about it",
	"updated the readme with the new install steps",
	"the tests pass locally but ci is flaky again",
	"i'll dig into the regression after this meeting",
	"good morning, anyone else seeing slow responses?",
	"lol that was a fun debugging session",
	"the new ui looks great, nice work",
	"can we move this discussion to a thread? getting long",
	"thanks, that was really helpful",
	"i'll write up a summary later today",
	"the staging deploy went through cleanly",
	"i think the issue is in the cache layer, not the api",
	"sure, happy to take a look this afternoon",
	"that explains the weird behavior i was seeing yesterday",
	"my flight lands at 6, will be back online after dinner",
	"the metrics dashboard is showing some weirdness on the p99",
}

// buildMarkovChain builds a simple 2-word forward Markov chain over
// the corpus. Returns a map from "w1 w2" -> list of possible next
// words. Sentence start and end are encoded as the empty key.
func buildMarkovChain() map[string][]string {
	chain := map[string][]string{}
	for _, line := range markovCorpus {
		words := strings.Fields(line)
		if len(words) == 0 {
			continue
		}
		// Start state.
		key := ""
		chain[key] = append(chain[key], words[0])
		if len(words) >= 2 {
			chain[words[0]] = append(chain[words[0]], words[1])
		}
		for i := 2; i < len(words); i++ {
			key := words[i-2] + " " + words[i-1]
			chain[key] = append(chain[key], words[i])
		}
		// End-of-sentence marker for the last bigram.
		if len(words) >= 2 {
			key := words[len(words)-2] + " " + words[len(words)-1]
			chain[key] = append(chain[key], "")
		}
	}
	return chain
}

var markovChain = buildMarkovChain()

func intToStrLocal(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// markovSentence draws one synthesized sentence from the chain.
// Cap length at maxWords to avoid runaway when the chain loops.
func markovSentence(rng *rand.Rand, maxWords int) string {
	var out []string
	// Pick a starter from the chain root.
	starts := markovChain[""]
	if len(starts) == 0 {
		return "hello"
	}
	w := starts[rng.Intn(len(starts))]
	out = append(out, w)
	prev := ""
	for i := 1; i < maxWords; i++ {
		key := prev + " " + w
		if prev == "" {
			key = w
		}
		next := markovChain[key]
		if len(next) == 0 {
			break
		}
		nxt := next[rng.Intn(len(next))]
		if nxt == "" {
			break
		}
		out = append(out, nxt)
		prev, w = w, nxt
	}
	return strings.Join(out, " ")
}

// MarkovBenign is a richer benign scenario than BenignChat: each
// message is a fresh Markov-generated sentence, so the L3 classifier
// sees variety in MsgLenMean / DistinctHashes / UpperRatioMean
// instead of training on the same 7 hard-coded strings. Use this for
// production training runs.
var MarkovBenign = Scenario{
	Name:        "markov-benign",
	Label:       LabelBenign,
	NickPrefix:  "irc",
	Description: "naturalistic chat synthesised from a 2-word Markov chain",
	Generate: func(uid, nick string, startAt time.Time, rng *rand.Rand) []*events.Event {
		evs := connectAndRegister(uid, nick, startAt, nick, true)
		ch := "#general"
		evs = append(evs, ev(events.EventJoin, uid, nick, startAt.Add(2*time.Second), func(e *events.Event) {
			e.Channel = ch
		}))
		const messages = 12
		seen := map[string]bool{}
		for i := 0; i < messages; i++ {
			gap := time.Duration(10+rng.Intn(50)) * time.Second
			at := startAt.Add(2*time.Second + gap*time.Duration(i+1))
			var text string
			// Reroll up to a few times if the chain emits a string
			// we already used this scenario. A small corpus inevitably
			// repeats and would trip the L1 repeat heuristic.
			for tries := 0; tries < 8; tries++ {
				text = markovSentence(rng, 12+rng.Intn(8))
				if !seen[text] {
					break
				}
			}
			// Last resort: salt with the index so it's at least unique.
			if seen[text] {
				text = text + " " + intToStrLocal(i)
			}
			seen[text] = true
			evs = append(evs, ev(events.EventChanMsg, uid, nick, at, func(e *events.Event) {
				e.Channel = ch
				e.Text = text
			}))
		}
		evs = append(evs, ev(events.EventPart, uid, nick, startAt.Add(15*time.Minute), func(e *events.Event) {
			e.Channel = ch
		}))
		return evs
	},
}

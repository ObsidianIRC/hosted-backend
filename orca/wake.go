package orca

import (
	"os"
	"regexp"
	"strings"
)

// punctuation between wake-word tokens (Whisper loves writing "Hey, Orca.
// Can you...") would defeat a plain HasPrefix check. Collapse all
// non-letter/non-digit runs to single spaces before matching.
var wakeNormalize = regexp.MustCompile(`[^\p{L}\p{N}]+`)

type wakeMatcher struct {
	phrases []string
}

func newWakeMatcher() *wakeMatcher {
	src := os.Getenv("ORCA_WAKE_WORDS")
	if src == "" {
		// Defaults include common Whisper mis-hearings of "Orca" so
		// the bot still responds when STT fumbles the proper noun.
		// Whisper-tiny especially mangles it: "oka", "orga", "okra",
		// "awker", "heioka" all show up in real transcripts.
		src = strings.Join([]string{
			"hey orca", "hi orca", "orca", "okay orca", "ok orca",
			"hey oka", "hey okra", "hey orga", "hey awker", "hey arca",
			"heioka", "hayoka", "oka", "orga", "okra", "awker", "arca",
		}, ",")
	}
	var phrases []string
	for _, p := range strings.Split(src, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			phrases = append(phrases, p)
		}
	}
	return &wakeMatcher{phrases: phrases}
}

// match returns (matched, query). If the utterance opens with one of the
// wake phrases, the residual text (the query) is returned with the wake
// trimmed off. Punctuation around the wake word is tolerated.
func (m *wakeMatcher) match(transcript string) (bool, string) {
	// Normalize: lowercase, collapse all non-letter/digit runs to a
	// single space. So "Hey, Orca. Can you hear me?" and
	// "hey  orca!! can you hear me" both become "hey orca can you hear me".
	t := strings.ToLower(strings.TrimSpace(transcript))
	t = strings.TrimSpace(wakeNormalize.ReplaceAllString(t, " "))
	for _, p := range m.phrases {
		normP := strings.TrimSpace(wakeNormalize.ReplaceAllString(p, " "))
		// Match the wake phrase as a full word(s) prefix: either the
		// whole utterance is the wake phrase, or it's followed by a
		// space (so "orca" doesn't false-match "orcas live in pods").
		if t == normP {
			return true, ""
		}
		if strings.HasPrefix(t, normP+" ") {
			return true, strings.TrimSpace(t[len(normP)+1:])
		}
	}
	return false, ""
}

package orca

import (
	"os"
	"strings"
)

type wakeMatcher struct {
	phrases []string
}

func newWakeMatcher() *wakeMatcher {
	src := os.Getenv("ORCA_WAKE_WORDS")
	if src == "" {
		src = "hey orca,hi orca,orca,okay orca,ok orca"
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
	t := strings.ToLower(strings.TrimSpace(transcript))
	t = strings.Trim(t, ".,?!:;")
	for _, p := range m.phrases {
		if strings.HasPrefix(t, p) {
			rest := strings.TrimSpace(t[len(p):])
			rest = strings.TrimLeft(rest, ",.?!:;-")
			rest = strings.TrimSpace(rest)
			return true, rest
		}
	}
	return false, ""
}

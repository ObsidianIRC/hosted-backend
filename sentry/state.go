package sentry

import (
	"backend/sentry/events"
	"hash/fnv"
	"net"
	"strings"
	"sync"
	"time"
)

// stateConfig caps how much per-user history sentry keeps in memory.
// Sized to fit ~10k concurrently-tracked users at <50 MB.
const (
	maxRecentMessages = 32 // sliding window of recent messages per user
	maxRecentJoins    = 16 // sliding window of recent channel joins per user
	maxRecentEvents   = 64 // sliding window of any-event timestamps for rate calc
)

// userState aggregates everything sentry has learned about one
// in-session user. Keyed by UID (stable across nick changes); a
// secondary nick -> uid map lives on the Manager.
type userState struct {
	mu sync.RWMutex

	UID         string
	FirstSeen   time.Time
	Nick        string
	Ident       string
	Host        string
	IP          net.IP
	Account     string
	IsTLS       bool

	// Aggregates -- updated on each event.
	MsgCount     int            // total messages (channel + user) since connect
	JoinCount    int            // total channel joins since connect
	PartCount    int            // total channel parts since connect
	NickCount    int            // total nick changes since connect
	CTCPCount    int            // total CTCP requests sent
	LastMsg      time.Time
	LastJoin     time.Time
	LastActivity time.Time

	// Sliding windows for the heuristic layer.
	recentMsgs   []messageRecord
	recentJoins  []joinRecord
	recentEvents []time.Time

	// Per-channel message counts (cleared on flushes).
	perChannelMsgs map[string]int

	// Hashes of recent messages -- repeat-message detection.
	msgHashes map[uint64]int

	// Cached features (computed lazily, invalidated on event).
	cachedFeatures *FeatureVector
}

type messageRecord struct {
	At      time.Time
	Channel string
	Text    string
	Hash    uint64
}

type joinRecord struct {
	At      time.Time
	Channel string
}

// FeatureVector is the numeric extraction handed to L2/L3. Always
// derived from a userState snapshot. New features should be appended
// (don't reorder existing slots so persisted L3 weights stay valid).
type FeatureVector struct {
	AgeOnNetworkSec float64 // seconds since FirstSeen
	MsgRatePerMin   float64 // messages per minute over the recent window
	JoinRatePerMin  float64 // joins per minute over the recent window
	MsgLenMean      float64 // mean message length in the recent window
	MsgLenVar       float64 // variance of message length
	DistinctHashes  float64 // count of distinct message hashes / total
	UniqueChannels  float64 // distinct channels messaged in
	HasAccount      float64 // 1 if logged in, else 0
	IsTLS           float64 // 1 if TLS, else 0
	UpperRatioMean  float64 // mean fraction of uppercase letters per message
	URLCount        float64 // count of URLs in recent window
	CTCPCount       float64 // CTCPs sent in recent window
	IdleBurstScore  float64 // see computeFeatures -- catches "lurk then spam"
}

// hashText returns a 64-bit FNV hash of the lowercased, whitespace-
// normalized message body. Used for repeat-message detection.
func hashText(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(strings.ToLower(strings.Join(strings.Fields(s), " "))))
	return h.Sum64()
}

// touch updates the basic activity bookkeeping. Caller holds u.mu.
func (u *userState) touch(at time.Time) {
	u.LastActivity = at
	if cap(u.recentEvents) == 0 {
		u.recentEvents = make([]time.Time, 0, maxRecentEvents)
	}
	u.recentEvents = append(u.recentEvents, at)
	if len(u.recentEvents) > maxRecentEvents {
		u.recentEvents = u.recentEvents[len(u.recentEvents)-maxRecentEvents:]
	}
	u.cachedFeatures = nil
}

// onMessage records a message, both for stats and the heuristic
// sliding window. Caller must NOT hold u.mu.
func (u *userState) onMessage(ev *events.Event) {
	u.mu.Lock()
	defer u.mu.Unlock()
	at := ev.At()
	u.touch(at)
	u.MsgCount++
	u.LastMsg = at

	h := hashText(ev.Text)
	if u.msgHashes == nil {
		u.msgHashes = map[uint64]int{}
	}
	u.msgHashes[h]++

	if u.perChannelMsgs == nil {
		u.perChannelMsgs = map[string]int{}
	}
	if ev.Channel != "" {
		u.perChannelMsgs[ev.Channel]++
	}

	rec := messageRecord{At: at, Channel: ev.Channel, Text: ev.Text, Hash: h}
	if cap(u.recentMsgs) == 0 {
		u.recentMsgs = make([]messageRecord, 0, maxRecentMessages)
	}
	u.recentMsgs = append(u.recentMsgs, rec)
	if len(u.recentMsgs) > maxRecentMessages {
		// Decrement the hash bucket of the message we're evicting.
		evicted := u.recentMsgs[0]
		if c, ok := u.msgHashes[evicted.Hash]; ok {
			if c <= 1 {
				delete(u.msgHashes, evicted.Hash)
			} else {
				u.msgHashes[evicted.Hash] = c - 1
			}
		}
		u.recentMsgs = u.recentMsgs[1:]
	}
}

// onJoin records a channel join.
func (u *userState) onJoin(ev *events.Event) {
	u.mu.Lock()
	defer u.mu.Unlock()
	at := ev.At()
	u.touch(at)
	u.JoinCount++
	u.LastJoin = at

	rec := joinRecord{At: at, Channel: ev.Channel}
	if cap(u.recentJoins) == 0 {
		u.recentJoins = make([]joinRecord, 0, maxRecentJoins)
	}
	u.recentJoins = append(u.recentJoins, rec)
	if len(u.recentJoins) > maxRecentJoins {
		u.recentJoins = u.recentJoins[1:]
	}
}

// onPart / onNick / onCTCP are similar bookkeeping for completeness.
func (u *userState) onPart(ev *events.Event) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.touch(ev.At())
	u.PartCount++
}

func (u *userState) onNick(ev *events.Event) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.touch(ev.At())
	u.NickCount++
	if ev.Nick != "" {
		u.Nick = ev.Nick
	}
}

func (u *userState) onCTCP(ev *events.Event) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.touch(ev.At())
	u.CTCPCount++
}

// snapshotFeatures returns the current FeatureVector. Computed
// lazily and cached until the next event invalidates the cache.
func (u *userState) snapshotFeatures(now time.Time) FeatureVector {
	u.mu.RLock()
	if u.cachedFeatures != nil {
		fv := *u.cachedFeatures
		u.mu.RUnlock()
		return fv
	}
	u.mu.RUnlock()

	u.mu.Lock()
	defer u.mu.Unlock()

	if u.cachedFeatures != nil {
		return *u.cachedFeatures
	}
	fv := computeFeatures(u, now)
	u.cachedFeatures = &fv
	return fv
}

// computeFeatures derives the L2/L3 feature vector from the user's
// current sliding-window state. New features must be appended, not
// reordered: persisted L3 weights index by position.
func computeFeatures(u *userState, now time.Time) FeatureVector {
	fv := FeatureVector{}
	fv.AgeOnNetworkSec = now.Sub(u.FirstSeen).Seconds()
	if u.Account != "" && u.Account != "*" {
		fv.HasAccount = 1
	}
	if u.IsTLS {
		fv.IsTLS = 1
	}

	// Sliding-window rates.
	winStart := now.Add(-60 * time.Second)
	msgsInWin := 0
	joinsInWin := 0
	var lenSum, lenSumSq float64
	upperSum := 0.0
	urlCount := 0.0
	distinctHashes := map[uint64]bool{}
	channelSet := map[string]bool{}
	for _, m := range u.recentMsgs {
		if m.At.Before(winStart) {
			continue
		}
		msgsInWin++
		l := float64(len(m.Text))
		lenSum += l
		lenSumSq += l * l
		upperSum += upperRatio(m.Text)
		urlCount += float64(countURLs(m.Text))
		distinctHashes[m.Hash] = true
		channelSet[m.Channel] = true
	}
	for _, j := range u.recentJoins {
		if j.At.Before(winStart) {
			continue
		}
		joinsInWin++
	}
	fv.MsgRatePerMin = float64(msgsInWin)
	fv.JoinRatePerMin = float64(joinsInWin)
	fv.URLCount = urlCount
	fv.UniqueChannels = float64(len(channelSet))
	if msgsInWin > 0 {
		fv.MsgLenMean = lenSum / float64(msgsInWin)
		fv.MsgLenVar = (lenSumSq / float64(msgsInWin)) - (fv.MsgLenMean * fv.MsgLenMean)
		fv.UpperRatioMean = upperSum / float64(msgsInWin)
		fv.DistinctHashes = float64(len(distinctHashes)) / float64(msgsInWin)
	}

	// Idle-burst score: very high if the user has been on net for a
	// while with low activity AND just produced a burst. Captures
	// the classic "lurk then spam" attack shape.
	if fv.AgeOnNetworkSec > 600 && msgsInWin >= 5 {
		// More age + sudden burst => higher score.
		fv.IdleBurstScore = (fv.AgeOnNetworkSec / 600) * float64(msgsInWin) / 5.0
	}
	fv.CTCPCount = float64(u.CTCPCount)

	return fv
}

// upperRatio returns the fraction of letters that are uppercase.
func upperRatio(s string) float64 {
	if s == "" {
		return 0
	}
	upper, letters := 0, 0
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			letters++
			if r >= 'A' && r <= 'Z' {
				upper++
			}
		}
	}
	if letters == 0 {
		return 0
	}
	return float64(upper) / float64(letters)
}

// countURLs is a cheap approximate URL counter.
func countURLs(s string) int {
	n := 0
	low := strings.ToLower(s)
	for _, sub := range []string{"http://", "https://", "www."} {
		n += strings.Count(low, sub)
	}
	return n
}

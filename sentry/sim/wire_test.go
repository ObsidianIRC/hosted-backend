package sim_test

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"backend/sentry"
	"backend/sentry/heuristics"
)

// TestSocketWireFormatRoundTrip proves the on-disk wire protocol the
// obbyircd sentinel.c module uses (newline-delimited JSON with keys
// like t, kind, nick, uid, channel, text) is consumed correctly by
// the Go pipeline. We don't run sentinel.c here -- we hand-write the
// exact JSON lines it emits and verify the manager observes them.
func TestSocketWireFormatRoundTrip(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "sentry.sock")

	collected := make(chan heuristics.Alert, 16)
	sink := alertChannelSink{ch: collected}
	mgr := sentry.NewManager(sentry.WithSink(&sink))

	srv := sentry.NewSocketServer(sock, mgr)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = srv.Run(ctx) }()
	defer func() {
		srv.Stop()
		cancel()
		wg.Wait()
	}()

	// Wait for the listener to be up.
	deadline := time.Now().Add(2 * time.Second)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", sock)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Emit the exact JSON shape sentinel.c writes. Mirrors keys in
	// /home/valerie/obbyircd/src/modules/sentinel.c put_subject().
	base := time.Unix(1_700_000_000, 0).UnixMilli()
	lines := []string{
		`{"t":` + intStr(base) + `,"kind":"connect","nick":"spammer","uid":"S001","ident":"sp","host":"sp.example","ip":"1.2.3.4"}`,
		`{"t":` + intStr(base+50) + `,"kind":"register","nick":"spammer","uid":"S001","ident":"sp","host":"sp.example","ip":"1.2.3.4"}`,
		`{"t":` + intStr(base+1000) + `,"kind":"join","nick":"spammer","uid":"S001","channel":"#general"}`,
	}
	// 31 flood messages, 100ms apart -- well above the 30/min threshold.
	for i := 0; i < 31; i++ {
		ts := base + int64(2000+i*100)
		lines = append(lines,
			`{"t":`+intStr(ts)+`,"kind":"chanmsg","nick":"spammer","uid":"S001","channel":"#general","text":"msg `+intStr(int64(i))+`"}`,
		)
	}
	for _, line := range lines {
		if _, err := conn.Write([]byte(line + "\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// Wait for at least one flood alert.
	deadline = time.Now().Add(2 * time.Second)
	var sawFlood bool
	for time.Now().Before(deadline) && !sawFlood {
		select {
		case a := <-collected:
			if a.Kind == "flood" && a.UID == "S001" {
				sawFlood = true
			}
		case <-time.After(50 * time.Millisecond):
		}
	}
	if !sawFlood {
		t.Fatalf("never received flood alert from socket-delivered JSON")
	}
}

type alertChannelSink struct {
	ch chan heuristics.Alert
}

func (s *alertChannelSink) Emit(alerts []heuristics.Alert) {
	for _, a := range alerts {
		select {
		case s.ch <- a:
		default:
			// drop on full channel; test only needs to see flood once
		}
	}
}

func intStr(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return strings.TrimSpace(string(b[i:]))
}

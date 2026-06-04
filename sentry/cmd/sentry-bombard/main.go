// Command sentry-bombard drives synthetic attacks against a live
// obbyircd instance over real TLS-IRC, with each attacker session
// arriving from a unique spoofed source IP via WEBIRC. Used to
// stress-test the deployed sentry pipeline.
//
// Requires a `webirc` block in obbyircd.conf authorising the harness
// host's IP with a password.
//
// All traffic stays on the local network -- the spoofed IPs are
// purely metadata claimed via WEBIRC; we still TCP-connect from the
// harness host.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"backend/sentry/events"
	"backend/sentry/sim"
)

func main() {
	var (
		addr        = flag.String("addr", "localhost:6664", "obbyircd TLS endpoint")
		serverHost  = flag.String("sni", "obby.t3ks.com", "SNI / WEBIRC hostname")
		webircPW    = flag.String("webirc-password", "", "matches the password in obbyircd webirc{} block")
		webircGate  = flag.String("webirc-gateway", "bombard", "name announced to obbyircd as the gateway")
		concurrency = flag.Int("concurrency", 6, "simultaneous attacker sessions")
		duration    = flag.Duration("duration", 0, "if >0, run continuously for this duration (e.g. 48h); supersedes -total")
		total       = flag.Int("total", 24, "in one-shot mode, total sessions before exit")
		scenName    = flag.String("scenario", "", "if set, run only this scenario (else random per session)")
		seedBase    = flag.Int64("seed", 0, "seed offset; defaults to time-based")
		verbose     = flag.Bool("v", false, "log per-line IRC traffic")
		ratePerSec  = flag.Float64("rate", 1.5, "scenarios kicked off per second (jittered ±50%)")
		benignFrac  = flag.Float64("benign-frac", 0.45, "fraction of sessions that are benign (0..1)")
		adminAPI    = flag.String("admin-api", "http://127.0.0.1:9601", "sentry admin API base for self-labeling")
		logEvery    = flag.Duration("log-every", 30*time.Second, "summary log cadence in -duration mode")
		victimPool  = flag.Int("victim-pool", 24, "long-lived idle benign sessions kept connected to receive PMs (0 disables)")
	)
	flag.Parse()

	if *webircPW == "" {
		log.Fatal("-webirc-password is required")
	}
	if *seedBase == 0 {
		*seedBase = time.Now().UnixNano()
	}

	// Mode: -scenario selects a specific named template (static set);
	// empty means procedural -- each session gets a freshly-randomised
	// scenario (counts, rates, channels, text, all varied).
	useProcedural := *scenName == ""

	// Static fallback pools (only used when -scenario filters in).
	var attackerPool, benignPool []sim.Scenario
	if !useProcedural {
		allCandidates := append([]sim.Scenario{}, sim.AllScenarios...)
		allCandidates = append(allCandidates, sim.AdversarialScenarios...)
		for _, s := range allCandidates {
			if s.Name != *scenName {
				continue
			}
			if s.Label == sim.LabelBenign {
				benignPool = append(benignPool, s)
			} else {
				attackerPool = append(attackerPool, s)
			}
		}
		if len(attackerPool)+len(benignPool) == 0 {
			log.Fatalf("no scenarios match selector %q", *scenName)
		}
		log.Printf("bombard: STATIC mode -- %v / %v",
			scenarioNames(attackerPool), scenarioNames(benignPool))
	} else {
		log.Printf("bombard: PROCEDURAL mode -- every session is a fresh randomised scenario")
	}

	log.Printf("bombard: concurrency=%d, rate=%.1f/s, benignFrac=%.2f",
		*concurrency, *ratePerSec, *benignFrac)

	// Shared HTTP client for self-labeling.
	apiClient := &http.Client{Timeout: 4 * time.Second}

	ctx, cancel := context.WithCancel(context.Background())
	// SIGINT/SIGTERM gracefully stops the loop.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh
		log.Printf("bombard: signal received, draining")
		cancel()
	}()
	if *duration > 0 {
		go func() {
			t := time.NewTimer(*duration)
			defer t.Stop()
			select {
			case <-t.C:
				log.Printf("bombard: duration elapsed, draining")
				cancel()
			case <-ctx.Done():
			}
		}()
	}

	var counter uint64
	var attackerCount uint64
	var benignCount uint64
	var errorCount uint64

	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	rng := rand.New(rand.NewSource(*seedBase))

	// Victim pool: long-lived idle benign sessions that stay connected
	// so PM-based attack scenarios have real addressable nicks. Without
	// these, PRIVMSG-to-user generates ERR_NOSUCHNICK and never trips
	// HOOKTYPE_USERMSG in sentinel.c.
	victims := newVictimPool()
	if *victimPool > 0 {
		log.Printf("bombard: spinning up %d victim sessions", *victimPool)
		for i := 0; i < *victimPool; i++ {
			vnick := fmt.Sprintf("idle_%s%d", randomVictimStem(rng), 1000+i)
			go runVictim(ctx, *addr, *serverHost, *webircPW, *webircGate,
				randomMaliciousIP(rng), vnick, victims, i, *verbose)
		}
		// Give the pool a moment to register before PMs start.
		time.Sleep(2 * time.Second)
	}

	// Logging goroutine for the long-running case.
	if *duration > 0 {
		go func() {
			t := time.NewTicker(*logEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					log.Printf("bombard: running -- total=%d attackers=%d benigns=%d errors=%d",
						atomic.LoadUint64(&counter),
						atomic.LoadUint64(&attackerCount),
						atomic.LoadUint64(&benignCount),
						atomic.LoadUint64(&errorCount))
				}
			}
		}()
	}

	startedAt := time.Now()
	for {
		// Stop condition.
		if *duration == 0 && int(counter) >= *total {
			break
		}
		select {
		case <-ctx.Done():
			goto drain
		default:
		}

		// Intensity wave: rate breathes between 0.3x and 1.7x the
		// configured base, with a 47-minute primary cycle and a
		// secondary 11-minute cycle. Mimics real-world traffic
		// where bursts of abuse alternate with quiet periods.
		elapsed := time.Since(startedAt).Minutes()
		primary := 0.7 * sinish(elapsed/47.0)
		secondary := 0.3 * sinish(elapsed/11.0)
		intensity := 1.0 + primary + secondary
		if intensity < 0.2 {
			intensity = 0.2
		}
		effectiveRate := *ratePerSec * intensity

		// Jittered pacing: 50%..150% of the wave-modulated rate.
		base := time.Duration(float64(time.Second) / effectiveRate)
		jitter := time.Duration(float64(base) * (0.5 + rng.Float64()))
		select {
		case <-ctx.Done():
			goto drain
		case <-time.After(jitter):
		}

		// Slot acquisition.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			goto drain
		}

		i := atomic.AddUint64(&counter, 1) - 1
		// Benign-fraction also breathes a little: between -0.1 and
		// +0.1 of the configured fraction, so some windows skew more
		// attacker-heavy (raid-like) and others more benign-heavy
		// (a normal IRC channel).
		benignFracNow := *benignFrac + 0.1*sinish(elapsed/29.0)
		if benignFracNow < 0.1 {
			benignFracNow = 0.1
		}
		if benignFracNow > 0.9 {
			benignFracNow = 0.9
		}

		// Pick attacker or benign.
		var scen sim.Scenario
		isAttacker := rng.Float64() >= benignFracNow
		if useProcedural {
			if isAttacker {
				scen = sim.ProceduralAttacker(rng)
			} else {
				scen = sim.ProceduralBenign(rng)
			}
		} else if isAttacker && len(attackerPool) > 0 {
			scen = attackerPool[rng.Intn(len(attackerPool))]
		} else if len(benignPool) > 0 {
			scen = benignPool[rng.Intn(len(benignPool))]
			isAttacker = false
		} else if len(attackerPool) > 0 {
			scen = attackerPool[rng.Intn(len(attackerPool))]
			isAttacker = true
		}
		if isAttacker {
			atomic.AddUint64(&attackerCount, 1)
		} else {
			atomic.AddUint64(&benignCount, 1)
		}

		seed := *seedBase + int64(i)*7919
		ip := randomMaliciousIP(rng)
		nick := fmt.Sprintf("%s%d", scen.NickPrefix, i)

		wg.Add(1)
		go func(i uint64, scen sim.Scenario, isAttacker bool, nick, ip string, seed int64) {
			defer wg.Done()
			defer func() { <-sem }()
			a := &attacker{
				addr:       *addr,
				sni:        *serverHost,
				ip:         ip,
				host:       fmt.Sprintf("bombard-%d.host", i),
				webircPW:   *webircPW,
				webircGate: *webircGate,
				nick:       nick,
				verbose:    *verbose,
				victims:    victims,
			}
			// Label-after-connect hook: bombard publishes the verdict
			// as soon as sentry has registered this user, so even
			// when sentry KILLs the session mid-scenario, the
			// training label still lands. The closure is invoked by
			// attacker.run() right after registration succeeds.
			labelHook := func() {
				if *adminAPI == "" {
					return
				}
				verdict := "bad"
				if !isAttacker {
					verdict = "good"
				}
				body, _ := json.Marshal(map[string]string{
					"nick":       nick,
					"verdict":    verdict,
					"source":     "bombard",
					"evidence":   scen.Name,
					"alert_kind": scen.Name,
				})
				req, _ := http.NewRequest("POST", *adminAPI+"/v1/label", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if resp, err := apiClient.Do(req); err == nil {
					resp.Body.Close()
				}
			}
			a.labelHook = labelHook
			if err := a.run(scen, seed); err != nil {
				atomic.AddUint64(&errorCount, 1)
				if *verbose {
					log.Printf("[#%d %s/%s] %v", i, scen.Name, nick, err)
				}
				return
			}
		}(i, scen, isAttacker, nick, ip, seed)
	}
drain:
	cancel()
	wg.Wait()
	log.Printf("bombard finished: total=%d attackers=%d benigns=%d errors=%d",
		atomic.LoadUint64(&counter),
		atomic.LoadUint64(&attackerCount),
		atomic.LoadUint64(&benignCount),
		atomic.LoadUint64(&errorCount))
}

func scenarioNames(ss []sim.Scenario) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Name
	}
	return out
}

// sinish is a tiny triangular oscillator in [-1, 1] keyed on a unit
// argument (turns). Avoids dragging math/Sin into the hot path and
// is plenty smooth for traffic shaping.
func sinish(turns float64) float64 {
	t := turns - float64(int(turns))
	if t < 0 {
		t += 1
	}
	// Triangle wave: 0->1 over first half, 1->-1 over middle, back to 0.
	if t < 0.25 {
		return 4 * t
	}
	if t < 0.75 {
		return 2 - 4*t
	}
	return -4 + 4*t
}

// randomMaliciousIP picks a pseudo-random IPv4 from a few prefixes
// known to host malicious traffic in the real world (Tor exits,
// known abusers' ASNs). Purely synthetic -- no packets actually go
// to these IPs from the harness host.
func randomMaliciousIP(rng *rand.Rand) string {
	prefixes := []string{"45.83.", "185.220.", "192.42.", "5.255.", "23.129.", "171.25."}
	p := prefixes[rng.Intn(len(prefixes))]
	return fmt.Sprintf("%s%d.%d", p, rng.Intn(256), 1+rng.Intn(254))
}

// attacker is one synthetic session.
type attacker struct {
	addr, sni, ip, host  string
	webircPW, webircGate string
	nick                 string
	verbose              bool
	victims              *victimPoolReg
	// labelHook, if non-nil, is invoked once registration completes
	// so the training label is captured even if sentry KILLs the
	// session before the scenario finishes.
	labelHook func()

	conn *tls.Conn
	rw   *bufio.ReadWriter
	mu   sync.Mutex
}

// victimPoolReg is a thread-safe registry of currently-connected
// idle victim nicks. PM scenarios pull a random target from here.
type victimPoolReg struct {
	mu    sync.RWMutex
	nicks map[string]bool
}

func newVictimPool() *victimPoolReg {
	return &victimPoolReg{nicks: map[string]bool{}}
}

func (v *victimPoolReg) add(n string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nicks[n] = true
}

func (v *victimPoolReg) remove(n string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.nicks, n)
}

func (v *victimPoolReg) pick(rng *rand.Rand) string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.nicks) == 0 {
		return ""
	}
	idx := rng.Intn(len(v.nicks))
	i := 0
	for n := range v.nicks {
		if i == idx {
			return n
		}
		i++
	}
	return ""
}

func randomVictimStem(rng *rand.Rand) string {
	stems := []string{"viv", "cara", "iggy", "milo", "june", "remy",
		"sage", "tian", "kai", "rio", "wren", "zane", "ash", "ada",
		"finn", "ivy", "leo", "mae", "noa", "ozzy"}
	return stems[rng.Intn(len(stems))]
}

// runVictim keeps a single benign idle session connected so it can
// serve as a PM target. Reconnects on disconnect; pumps PINGs.
func runVictim(ctx context.Context, addr, sni, webircPW, webircGate,
	ip, nick string, pool *victimPoolReg, idx int, verbose bool) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		a := &attacker{
			addr: addr, sni: sni, ip: ip,
			host:       fmt.Sprintf("victim-%d.pool", idx),
			webircPW:   webircPW,
			webircGate: webircGate,
			nick:       nick,
			verbose:    verbose,
		}
		if err := a.connect(); err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		// Join one channel so the session is fully visible.
		_ = a.send("JOIN #lobby")
		pool.add(nick)
		// Pump PINGs and silently ignore everything else until ctx ends
		// or the read errors out.
		for {
			select {
			case <-ctx.Done():
				pool.remove(nick)
				_ = a.send("QUIT :victim shutdown")
				_ = a.conn.Close()
				return
			default:
			}
			_ = a.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			line, err := a.rw.ReadString('\n')
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				break
			}
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, "PING ") {
				_ = a.send("PONG " + strings.TrimPrefix(line, "PING "))
			}
		}
		pool.remove(nick)
		_ = a.conn.Close()
		// Backoff before reconnect.
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func (a *attacker) connect() error {
	c, err := tls.Dial("tcp", a.addr, &tls.Config{
		ServerName:         a.sni,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	a.conn = c
	a.rw = bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	// WEBIRC must be the FIRST line -- before NICK/USER.
	if err := a.send(fmt.Sprintf("WEBIRC %s %s %s %s",
		a.webircPW, a.webircGate, a.host, a.ip)); err != nil {
		return err
	}
	if err := a.send("NICK " + a.nick); err != nil {
		return err
	}
	if err := a.send(fmt.Sprintf("USER %s 0 0 :%s", a.nick, a.nick)); err != nil {
		return err
	}
	// Wait for registration to complete. obbyircd may send either
	// 376 (RPL_ENDOFMOTD) or 422 (ERR_NOMOTD) -- match either.
	if err := a.waitForAny([]string{" 376 ", " 422 "}, 8*time.Second); err != nil {
		return err
	}
	// Fire the label hook NOW: the user is registered, sentry has
	// observed connect/register, the verdict can be persisted
	// regardless of how the scenario ends (including sentry KILL).
	if a.labelHook != nil {
		a.labelHook()
	}
	return nil
}

func (a *attacker) send(line string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.verbose {
		log.Printf(">> [%s] %s", a.nick, line)
	}
	_, err := a.rw.WriteString(line + "\r\n")
	if err == nil {
		err = a.rw.Flush()
	}
	return err
}

// waitForAny reads server lines until one contains any of the needles
// or the deadline elapses. Inline-handles PINGs to keep the connection
// alive.
func (a *attacker) waitForAny(needles []string, dur time.Duration) error {
	deadline := time.Now().Add(dur)
	_ = a.conn.SetReadDeadline(deadline)
	for {
		line, err := a.rw.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if a.verbose {
			log.Printf("<< [%s] %s", a.nick, line)
		}
		if strings.HasPrefix(line, "PING ") {
			_ = a.send("PONG " + strings.TrimPrefix(line, "PING "))
		}
		for _, n := range needles {
			if strings.Contains(line, n) {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %v", needles)
		}
	}
}

// run drives the synthetic scenario through real IRC commands. Events
// from sim.Scenario are translated: connect/register are implicit in
// the TLS+WEBIRC dance; everything else maps to a wire command.
func (a *attacker) run(s sim.Scenario, seed int64) error {
	if err := a.connect(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer a.conn.Close()

	// Background drain so the server doesn't block on our recv.
	stopDrain := make(chan struct{})
	go a.drain(stopDrain)
	defer close(stopDrain)

	rng := rand.New(rand.NewSource(seed))
	startAt := time.Now()
	evs := s.Generate(a.nick, a.nick, startAt, rng)

	// PM target strategy depends on the scenario label:
	//   pm_flood / nickserv_spoof / mention_storm with PMs -> lock to
	//      a single primary victim for the whole session
	//   pm_shotgun -> fresh random victim per PM
	//   everything else -> primary victim if any
	var primaryVictim string
	if a.victims != nil {
		primaryVictim = a.victims.pick(rng)
	}
	shotgun := string(s.Label) == "pm_shotgun"

	for i, ev := range evs {
		switch ev.Kind {
		case events.EventConnect, events.EventRegister:
			continue
		case events.EventJoin:
			_ = a.send("JOIN " + ev.Channel)
		case events.EventPart:
			_ = a.send("PART " + ev.Channel)
		case events.EventChanMsg:
			_ = a.send("PRIVMSG " + ev.Channel + " :" + ev.Text)
		case events.EventUserMsg:
			// Rewrite the scenario's synthetic target onto a real
			// nick from the victim pool so HOOKTYPE_USERMSG fires.
			// Shotgun-labeled scenarios pick a fresh victim per PM;
			// everything else hammers the primary victim (pm_flood,
			// nickserv_spoof, mention-via-pm).
			target := primaryVictim
			if shotgun && a.victims != nil {
				target = a.victims.pick(rng)
			}
			if target == "" && a.victims != nil {
				target = a.victims.pick(rng)
			}
			if target != "" {
				_ = a.send("PRIVMSG " + target + " :" + ev.Text)
			}
		case events.EventCTCP:
			_ = a.send("PRIVMSG " + ev.Channel + " :" + ev.Text)
		case events.EventNick:
			_ = a.send("NICK " + ev.Nick)
		case events.EventQuit:
			_ = a.send("QUIT :bombard done")
			return nil
		default:
			// Skip unsupported event kinds.
		}
		// Pace by the gap to the next event so timing-sensitive
		// rules (idle_burst, flood-over-60s) still see realistic
		// inter-arrival times.
		if i+1 < len(evs) {
			gap := time.Duration(evs[i+1].Time-ev.Time) * time.Millisecond
			if gap > 0 && gap < 30*time.Second {
				time.Sleep(gap)
			}
		}
	}
	_ = a.send("QUIT :bombard done")
	return nil
}

func (a *attacker) drain(stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		default:
		}
		_ = a.conn.SetReadDeadline(time.Now().Add(time.Second))
		line, err := a.rw.ReadString('\n')
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, "PING ") {
			_ = a.send("PONG " + strings.TrimPrefix(line, "PING "))
		}
		if a.verbose {
			log.Printf("<< [%s] %s", a.nick, line)
		}
	}
}

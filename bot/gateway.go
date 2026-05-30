package bot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Gateway struct {
	bot        Bot
	url        string
	conn       *websocket.Conn
	connMu     sync.Mutex
	sendMu     sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	heartbeat  time.Duration
	identified bool
	sessionID  string
	lastSeq    int64
}

func runBot(parent context.Context, b Bot, gatewayURL string) {
	backoff := time.Second
	for {
		if parent.Err() != nil {
			return
		}
		err := connectAndRun(parent, b, gatewayURL)
		if parent.Err() != nil {
			return
		}
		log.Printf("[bot/%s] disconnected: %v; reconnecting in %s", b.Nick(), err, backoff)
		select {
		case <-parent.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func connectAndRun(parent context.Context, b Bot, gatewayURL string) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	gw := &Gateway{bot: b, url: gatewayURL, ctx: ctx, cancel: cancel}

	if err := gw.dial(); err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer gw.close()

	if err := gw.readHello(); err != nil {
		return fmt.Errorf("hello: %w", err)
	}

	if err := gw.identify(); err != nil {
		return fmt.Errorf("identify: %w", err)
	}

	go gw.heartbeatLoop()

	return gw.readLoop()
}

func (g *Gateway) dial() error {
	u, err := url.Parse(g.url)
	if err != nil {
		return err
	}
	headers := http.Header{}
	headers.Set("User-Agent", "obbyircd-orca/0.1")
	c, _, err := websocket.DefaultDialer.DialContext(g.ctx, u.String(), headers)
	if err != nil {
		return err
	}
	g.connMu.Lock()
	g.conn = c
	g.connMu.Unlock()
	return nil
}

func (g *Gateway) close() {
	g.connMu.Lock()
	defer g.connMu.Unlock()
	if g.conn != nil {
		_ = g.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, "bye"),
			time.Now().Add(2*time.Second))
		_ = g.conn.Close()
		g.conn = nil
	}
}

func (g *Gateway) readHello() error {
	g.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, msg, err := g.conn.ReadMessage()
	if err != nil {
		return err
	}
	g.conn.SetReadDeadline(time.Time{})
	var f Frame
	if err := json.Unmarshal(msg, &f); err != nil {
		return err
	}
	if f.Op != OpHello {
		return fmt.Errorf("expected HELLO, got op %d", f.Op)
	}
	var h Hello
	if err := json.Unmarshal(f.D, &h); err != nil {
		return err
	}
	if h.HeartbeatIntervalMs <= 0 {
		h.HeartbeatIntervalMs = 30000
	}
	g.heartbeat = time.Duration(h.HeartbeatIntervalMs) * time.Millisecond
	return nil
}

func (g *Gateway) identify() error {
	d, _ := json.Marshal(IdentifyD{Token: g.bot.Token()})
	return g.send(Frame{Op: OpIdentify, D: d})
}

func (g *Gateway) heartbeatLoop() {
	t := time.NewTicker(g.heartbeat)
	defer t.Stop()
	for {
		select {
		case <-g.ctx.Done():
			return
		case <-t.C:
			if err := g.send(Frame{Op: OpHeartbeat}); err != nil {
				g.cancel()
				return
			}
		}
	}
}

func (g *Gateway) send(f Frame) error {
	g.sendMu.Lock()
	defer g.sendMu.Unlock()
	g.connMu.Lock()
	conn := g.conn
	g.connMu.Unlock()
	if conn == nil {
		return errors.New("not connected")
	}
	return conn.WriteJSON(f)
}

func (g *Gateway) sendInteractionResponse(id, content, vis string, ephemeral bool) error {
	d, _ := json.Marshal(InteractionResponse{
		ID:         id,
		Content:    content,
		Visibility: vis,
		Ephemeral:  ephemeral,
	})
	return g.send(Frame{Op: OpInteractionResponse, D: d})
}

func (g *Gateway) sendWorkflowEvent(target string, payload json.RawMessage) error {
	d, _ := json.Marshal(WorkflowEventOut{Target: target, Payload: payload})
	return g.send(Frame{Op: OpWorkflowEvent, D: d})
}

func (g *Gateway) readLoop() error {
	for {
		_, msg, err := g.conn.ReadMessage()
		if err != nil {
			return err
		}
		var f Frame
		if err := json.Unmarshal(msg, &f); err != nil {
			log.Printf("[bot/%s] bad frame: %v", g.bot.Nick(), err)
			continue
		}
		g.handleFrame(f)
	}
}

func (g *Gateway) handleFrame(f Frame) {
	switch f.Op {
	case OpHeartbeatAck:
		return
	case OpInvalidSession:
		g.cancel()
		return
	case OpReconnect:
		g.cancel()
		return
	case OpDispatch:
		if f.Seq > g.lastSeq {
			g.lastSeq = f.Seq
		}
		g.handleDispatch(f.Type, f.D)
	}
}

func (g *Gateway) handleDispatch(eventName string, data json.RawMessage) {
	switch eventName {
	case "READY":
		var r Ready
		_ = json.Unmarshal(data, &r)
		g.identified = true
		g.sessionID = r.SessionID
		log.Printf("[bot/%s] ready as %s (session %s)", g.bot.Nick(), r.Nick, r.SessionID)
		g.afterReady()
	case "COMMAND_INVOKE":
		g.handleInvoke(data)
	default:
		g.bot.OnEvent(g.ctx, eventName, data)
	}
}

func (g *Gateway) afterReady() {
	cmds := g.bot.Commands()
	if len(cmds) > 0 {
		d, _ := json.Marshal(CommandRegisterD{Commands: cmds, Prefix: g.bot.Prefix()})
		if err := g.send(Frame{Op: OpCommandRegister, D: d}); err != nil {
			log.Printf("[bot/%s] command register: %v", g.bot.Nick(), err)
		}
	}
}

func (g *Gateway) handleInvoke(data json.RawMessage) {
	var ci CommandInvoke
	if err := json.Unmarshal(data, &ci); err != nil {
		log.Printf("[bot/%s] bad COMMAND_INVOKE: %v", g.bot.Nick(), err)
		return
	}
	opts := map[string]any{}
	if len(ci.Options) > 0 {
		_ = json.Unmarshal(ci.Options, &opts)
	}
	inv := &Invocation{
		CommandInvoke: ci,
		OptionsMap:    opts,
		gw:            g,
	}
	go func() {
		if err := g.bot.OnInvoke(g.ctx, inv); err != nil {
			log.Printf("[bot/%s] OnInvoke %s: %v", g.bot.Nick(), ci.Command, err)
			_ = inv.Whisper("error: " + err.Error())
		}
	}()
}

// CommandNames lists configured commands as a comma-joined string for logging.
func CommandNames(cmds []Command) string {
	names := make([]string, len(cmds))
	for i, c := range cmds {
		names[i] = c.Name
	}
	return strings.Join(names, ",")
}

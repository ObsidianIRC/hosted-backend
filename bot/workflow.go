package bot

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync/atomic"
)

type WorkflowEmitter struct {
	gw      *Gateway
	target  string
	id      string
	name    string
	trigger string

	stepCounter atomic.Int64
	terminated  atomic.Bool
}

func newWorkflowEmitter(gw *Gateway, target, triggerMsgid, name string) *WorkflowEmitter {
	return &WorkflowEmitter{
		gw:      gw,
		target:  target,
		id:      randomID(8),
		name:    name,
		trigger: triggerMsgid,
	}
}

func (w *WorkflowEmitter) ID() string     { return w.id }
func (w *WorkflowEmitter) Target() string { return w.target }

// emit is nil-safe so callers that don't have a real workflow context
// (e.g. Orca's voice path invoking admin tools without a user-facing
// invocation) can pass a nil *WorkflowEmitter and get silent no-ops
// rather than panics. The public methods below propagate this by
// short-circuiting on a nil receiver.
func (w *WorkflowEmitter) emit(payload map[string]any) error {
	if w == nil {
		return nil
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	log.Printf("[workflow] emit wid=%s target=%s payload=%s", w.id, w.target, string(b))
	return w.gw.sendTagmsg(w.target, map[string]string{
		"+draft/bot-tools": base64.StdEncoding.EncodeToString(b),
	})
}

func (w *WorkflowEmitter) Start(features ...string) error {
	payload := map[string]any{
		"msg":   "workflow",
		"id":    w.id,
		"state": "start",
	}
	if w.name != "" {
		payload["name"] = w.name
	}
	if w.trigger != "" {
		payload["trigger"] = w.trigger
	}
	if len(features) > 0 {
		payload["features"] = features
	}
	return w.emit(payload)
}

func (w *WorkflowEmitter) WorkflowState(state string) error {
	if w == nil {
		return nil
	}
	if state == "complete" || state == "failed" || state == "cancelled" {
		w.terminated.Store(true)
	}
	return w.emit(map[string]any{
		"msg":   "workflow",
		"id":    w.id,
		"state": state,
	})
}

func (w *WorkflowEmitter) Complete() error {
	return w.WorkflowState("complete")
}

func (w *WorkflowEmitter) IsTerminated() bool {
	if w == nil {
		return true
	}
	return w.terminated.Load()
}

// TerminalReplyTags returns the outer client-only tags a final reply
// PRIVMSG should carry so the workflow completes together with the
// reply (per the bot-tools spec). Always includes +draft/bot-tools
// with the terminal workflow state; includes +draft/reply when the
// workflow was anchored to a trigger msgid. Marks the workflow
// terminated so a deferred Complete()/Failed() won't double-fire.
func (w *WorkflowEmitter) TerminalReplyTags(state string) map[string]string {
	if w == nil {
		return nil
	}
	if state != "complete" && state != "failed" && state != "cancelled" {
		state = "complete"
	}
	w.terminated.Store(true)
	body, _ := json.Marshal(map[string]any{
		"msg":   "workflow",
		"id":    w.id,
		"state": state,
	})
	tags := map[string]string{
		"+draft/bot-tools": base64.StdEncoding.EncodeToString(body),
	}
	if w.trigger != "" {
		tags["+draft/reply"] = w.trigger
	}
	return tags
}

func (w *WorkflowEmitter) Failed() error {
	return w.WorkflowState("failed")
}

func (w *WorkflowEmitter) Cancelled() error {
	return w.WorkflowState("cancelled")
}

func (w *WorkflowEmitter) nextSid() string {
	return "s" + itoa(w.stepCounter.Add(1))
}

type Step struct {
	w     *WorkflowEmitter
	sid   string
	stype string
	tool  string
	label string
}

func (w *WorkflowEmitter) Reasoning(text string) error {
	sid := w.nextSid()
	return w.emit(map[string]any{
		"msg":     "step",
		"wid":     w.id,
		"sid":     sid,
		"type":    "reasoning",
		"state":   "complete",
		"content": text,
	})
}

// ReasoningStart fires a reasoning:start immediately after Start() so
// the client renders a "thinking" indicator while the model is still
// composing the first tool call or text response. The returned *Step
// MUST be Complete()'d once the model has produced its first output,
// or the spinner spins forever.
func (w *WorkflowEmitter) ReasoningStart(text string) *Step {
	if w == nil {
		return nil
	}
	sid := w.nextSid()
	st := &Step{w: w, sid: sid, stype: "reasoning"}
	payload := map[string]any{
		"msg":   "step",
		"wid":   w.id,
		"sid":   sid,
		"type":  "reasoning",
		"state": "start",
	}
	if text != "" {
		payload["content"] = text
	}
	_ = w.emit(payload)
	return st
}

// Complete fires <stype>:complete for non-tool steps (reasoning, text).
// Tool calls should use (*Step).Result / (*Step).Failed instead.
func (s *Step) Complete() error {
	if s == nil {
		return nil
	}
	return s.w.emit(map[string]any{
		"msg":   "step",
		"wid":   s.w.id,
		"sid":   s.sid,
		"type":  s.stype,
		"state": "complete",
	})
}

func (w *WorkflowEmitter) StartToolCall(tool, label string, params any) *Step {
	if w == nil {
		return nil
	}
	sid := w.nextSid()
	st := &Step{w: w, sid: sid, stype: "tool-call", tool: tool, label: label}
	payload := map[string]any{
		"msg":   "step",
		"wid":   w.id,
		"sid":   sid,
		"type":  "tool-call",
		"state": "start",
		"tool":  tool,
	}
	if label != "" {
		payload["label"] = label
	}
	if params != nil {
		payload["content"] = params
	}
	_ = w.emit(payload)
	return st
}

func (s *Step) Result(summary string) error {
	if s == nil {
		return nil
	}
	resultSid := s.w.nextSid()
	if err := s.w.emit(map[string]any{
		"msg":     "step",
		"wid":     s.w.id,
		"sid":     resultSid,
		"type":    "tool-result",
		"state":   "complete",
		"tool":    s.tool,
		"content": summary,
	}); err != nil {
		return err
	}
	return s.w.emit(map[string]any{
		"msg":   "step",
		"wid":   s.w.id,
		"sid":   s.sid,
		"type":  "tool-call",
		"state": "complete",
		"tool":  s.tool,
	})
}

func (s *Step) Failed(reason string) error {
	if s == nil {
		return nil
	}
	if reason != "" {
		_ = s.w.emit(map[string]any{
			"msg":     "step",
			"wid":     s.w.id,
			"sid":     s.w.nextSid(),
			"type":    "tool-result",
			"state":   "failed",
			"tool":    s.tool,
			"content": reason,
		})
	}
	return s.w.emit(map[string]any{
		"msg":   "step",
		"wid":   s.w.id,
		"sid":   s.sid,
		"type":  "tool-call",
		"state": "failed",
		"tool":  s.tool,
	})
}

func (w *WorkflowEmitter) TextFragment(text string) error {
	return w.emit(map[string]any{
		"msg":     "step",
		"wid":     w.id,
		"sid":     w.nextSid(),
		"type":    "text",
		"state":   "running",
		"content": text,
	})
}

func randomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func itoa(n int64) string {
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

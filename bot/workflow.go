package bot

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

func (w *WorkflowEmitter) emit(payload map[string]any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return w.gw.sendWorkflowEvent(w.target, b)
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

func (w *WorkflowEmitter) StartToolCall(tool, label string, params any) *Step {
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

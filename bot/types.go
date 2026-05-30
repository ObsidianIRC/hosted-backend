package bot

import "encoding/json"

const (
	OpDispatch            = 0
	OpHeartbeat           = 1
	OpIdentify            = 2
	OpResume              = 6
	OpReconnect           = 7
	OpInvalidSession      = 9
	OpHello               = 10
	OpHeartbeatAck        = 11
	OpCommandRegister     = 20
	OpInteractionResponse = 21
	OpInteractionDefer    = 22
	OpWorkflowEvent       = 30
	OpSendMessage         = 31
)

type SendMessageD struct {
	Target   string `json:"target"`
	Content  string `json:"content"`
	IsNotice bool   `json:"is_notice,omitempty"`
}

type Frame struct {
	Op   int             `json:"op"`
	Seq  int64           `json:"s,omitempty"`
	Type string          `json:"t,omitempty"`
	D    json.RawMessage `json:"d,omitempty"`
}

type Hello struct {
	HeartbeatIntervalMs int `json:"heartbeat_interval"`
}

type IdentifyD struct {
	Token   string `json:"token"`
	Resume  string `json:"resume_session_id,omitempty"`
	LastSeq int64  `json:"last_seq,omitempty"`
}

type Ready struct {
	SessionID string `json:"session_id"`
	Nick      string `json:"nick"`
}

type Author struct {
	Nick    string `json:"nick"`
	Account string `json:"account"`
	Host    string `json:"host"`
	IsOper  bool   `json:"is_oper"`
}

type CommandInvoke struct {
	ID      string          `json:"id"`
	Command string          `json:"name"`
	Options json.RawMessage `json:"options"`
	Channel string          `json:"channel,omitempty"`
	Msgid   string          `json:"invoker_msgid"`
	Author  Author          `json:"invoker"`
}

type InteractionResponse struct {
	ID         string `json:"id"`
	Content    string `json:"content"`
	Visibility string `json:"visibility,omitempty"`
	Ephemeral  bool   `json:"ephemeral,omitempty"`
}

type WorkflowEventOut struct {
	Target  string          `json:"target"`
	Payload json.RawMessage `json:"payload"`
}

type WorkflowAction struct {
	WID     string          `json:"wid"`
	Action  string          `json:"action"`
	Target  string          `json:"target"`
	Content json.RawMessage `json:"content,omitempty"`
	From    Author          `json:"from"`
}

type Option struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description,omitempty"`
	Choices     []string `json:"choices,omitempty"`
}

type Requires struct {
	MinChannelRank string `json:"min-channel-rank,omitempty"`
	Account        bool   `json:"account,omitempty"`
	TLS            bool   `json:"tls,omitempty"`
}

type Command struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Contexts    []string  `json:"contexts"`
	Options     []Option  `json:"options,omitempty"`
	Requires    *Requires `json:"requires,omitempty"`
}

type CommandRegisterD struct {
	Commands []Command `json:"commands"`
	Prefix   string    `json:"prefix,omitempty"`
}

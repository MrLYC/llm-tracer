package model

type ProtocolType string

const (
	ProtocolSystemOne       ProtocolType = "systemone"
	ProtocolOpenAIChat      ProtocolType = "openai_chat"
	ProtocolOpenAIResponses ProtocolType = "openai_responses"
	ProtocolAnthropic       ProtocolType = "anthropic"
	ProtocolGemini          ProtocolType = "gemini"
	ProtocolOllama          ProtocolType = "ollama"
	ProtocolUnknown         ProtocolType = "unknown"
)

type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid,omitempty"`
	TID     int    `json:"tid,omitempty"`
	UID     int    `json:"uid,omitempty"`
	Comm    string `json:"comm,omitempty"`
	Cmdline string `json:"cmdline,omitempty"`
	Exe     string `json:"exe,omitempty"`
	Cwd     string `json:"cwd,omitempty"`
	TLSMode string `json:"tls_mode,omitempty"` // openssl_uprobe | gotls_uprobe | ld_preload | ecapture_ws | proxy_tap
}

type ScopeFilter struct {
	PIDs          []int    `json:"pids,omitempty"`
	PIDOnly       bool     `json:"pid_only"`
	Exes          []string `json:"exes,omitempty"`
	Cwds          []string `json:"cwds,omitempty"`
	Cmds          []string `json:"cmds,omitempty"`
	Hosts         []string `json:"hosts,omitempty"`
	RecordHeaders bool     `json:"record_headers"`
}

type SystemOneQuestion struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"` // choice | score | noul
	Goal         string            `json:"goal,omitempty"`
	Operation    string            `json:"operation,omitempty"`
	Guides       []string          `json:"guides,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
	OptionOrder  []string          `json:"option_order,omitempty"`
	AnswerChoice string            `json:"answer_choice,omitempty"`
	TopChoice    string            `json:"top_choice,omitempty"`
	UsedArgmax   bool              `json:"used_argmax,omitempty"`
	Confidence   float64           `json:"confidence"`
	Probs        map[string]float64 `json:"probabilities,omitempty"`
}

type SystemOnePageSummary struct {
	URL          string `json:"url,omitempty"`
	Title        string `json:"title,omitempty"`
	TextSnippet  string `json:"text_snippet,omitempty"`
	TextLen      int    `json:"text_len,omitempty"`
	ElementCount int    `json:"element_count"`
}

type SystemOneStepSummary struct {
	Model             string                 `json:"model"`
	Goal              string                 `json:"goal,omitempty"`
	Page              SystemOnePageSummary   `json:"page"`
	RecentActionCount int                    `json:"recent_action_count"`
	RecentActions     []map[string]any       `json:"recent_actions,omitempty"`
	SelectedOp        string                 `json:"selected_operation,omitempty"`
	SelectedTarget    string                 `json:"selected_target,omitempty"`
	SelectedElement   string                 `json:"selected_element,omitempty"`
	SelectedText      string                 `json:"selected_text,omitempty"`
	OpConfidence      float64                `json:"op_confidence"`
	TargetConfidence  float64                `json:"target_confidence,omitempty"`
	Questions         []SystemOneQuestion    `json:"questions,omitempty"`
	QuestionsUsed     []string               `json:"questions_used,omitempty"`
	FallbackReason    string                 `json:"fallback_reason,omitempty"`
}

type ToolCallItem struct {
	ID        string `json:"id,omitempty"`
	Name      string `json:"name"`
	Arguments string `json:"arguments,omitempty"`
}

type ChatMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content,omitempty"`
	Thinking   string         `json:"thinking,omitempty"`
	ToolCalls  []ToolCallItem `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type TokenUsage struct {
	InputTokens     int `json:"input_tokens,omitempty"`
	OutputTokens    int `json:"output_tokens,omitempty"`
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
	CachedTokens    int `json:"cached_tokens,omitempty"`
	TotalTokens     int `json:"total_tokens,omitempty"`
}

type ChatSummary struct {
	Model         string         `json:"model"`
	SystemPrompt  string         `json:"system_prompt,omitempty"`
	Messages      []ChatMessage  `json:"messages,omitempty"`
	NewMessages   []ChatMessage  `json:"new_messages,omitempty"`
	PrefixCount   int            `json:"prefix_count"`
	ResponseText  string         `json:"response_text,omitempty"`
	ReasoningText string         `json:"reasoning_text,omitempty"`
	ToolCalls     []ToolCallItem `json:"tool_calls,omitempty"`
	StopReason    string         `json:"stop_reason,omitempty"`
	IsStream      bool           `json:"is_stream"`
	Usage         TokenUsage     `json:"usage"`
}

type TraceEvent struct {
	ID                string                `json:"id"`
	SessionID         string                `json:"session_id"`
	ParentEventID     string                `json:"parent_event_id,omitempty"`
	StepIndex         int                   `json:"step_index"`
	TurnIndex         int                   `json:"turn_index"`
	CorrelationLevel  string                `json:"correlation_level"` // L1_explicit | L2_context | L3_proctree | root
	CorrelationReason string                `json:"correlation_reason,omitempty"`
	Timestamp         int64                 `json:"timestamp"` // unix ms
	DurationMs        int64                 `json:"duration_ms"`
	Status            string                `json:"status"` // streaming | ok | error
	HTTPStatus        int                   `json:"http_status,omitempty"`
	HTTPVersion       string                `json:"http_version,omitempty"`
	Method            string                `json:"method"`
	Host              string                `json:"host"`
	Path              string                `json:"path"`
	URL               string                `json:"url"`
	Protocol          ProtocolType          `json:"protocol"`
	Process           ProcessInfo           `json:"process"`
	HeadersRecorded   bool                  `json:"headers_recorded"`
	RequestHeaders    map[string]string     `json:"request_headers,omitempty"`
	ResponseHeaders   map[string]string     `json:"response_headers,omitempty"`
	RequestBytes      int                   `json:"request_bytes"`
	ResponseBytes     int                   `json:"response_bytes"`
	StreamChunks      int                   `json:"stream_chunks,omitempty"`
	SystemOne         *SystemOneStepSummary `json:"systemone,omitempty"`
	Chat              *ChatSummary          `json:"chat,omitempty"`
	RequestRaw        string                `json:"request_raw,omitempty"`
	ResponseRaw       string                `json:"response_raw,omitempty"`
	Error             string                `json:"error,omitempty"`
}

type SessionSummary struct {
	ID              string       `json:"id"`
	Title           string       `json:"title"`
	Goal            string       `json:"goal,omitempty"`
	PrimaryProtocol ProtocolType `json:"primary_protocol"`
	Protocols       []string     `json:"protocols"`
	Models          []string     `json:"models,omitempty"`
	RootPID         int          `json:"root_pid"`
	RootComm        string       `json:"root_comm,omitempty"`
	RootCmdline     string       `json:"root_cmdline,omitempty"`
	RootCwd         string       `json:"root_cwd,omitempty"`
	CreatedAt       int64        `json:"created_at"` // unix ms
	UpdatedAt       int64        `json:"updated_at"` // unix ms
	EventCount      int          `json:"event_count"`
	StepCount       int          `json:"step_count"`
	TurnCount       int          `json:"turn_count"`
	TotalTokens     int          `json:"total_tokens"`
	TotalDurationMs int64        `json:"total_duration_ms"`
	ErrorCount      int          `json:"error_count"`
	LastStatus      string       `json:"last_status"`
}

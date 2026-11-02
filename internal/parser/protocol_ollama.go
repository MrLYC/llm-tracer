package parser

import (
	"encoding/json"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/model"
)

// ParseOllama parses Ollama /api/chat and /api/generate payloads.
func ParseOllama(reqBody []byte, respBody []byte) (*model.ChatSummary, error) {
	chat := &model.ChatSummary{}
	var req map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &req) == nil {
		chat.Model = asString(req["model"])
		if s, ok := req["stream"].(bool); ok {
			chat.IsStream = s
		}
		if prompt := asString(req["prompt"]); prompt != "" {
			chat.Messages = append(chat.Messages, model.ChatMessage{Role: "user", Content: prompt})
		}
		if msgs, ok := req["messages"].([]any); ok {
			for _, m := range msgs {
				if mm, ok := m.(map[string]any); ok {
					cm := parseOpenAIMessage(mm)
					if cm.Role == "system" && chat.SystemPrompt == "" {
						chat.SystemPrompt = cm.Content
					}
					chat.Messages = append(chat.Messages, cm)
				}
			}
		}
	}
	var textBuf, thinkBuf strings.Builder
	for _, line := range strings.Split(string(respBody), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var chunk map[string]any
		if json.Unmarshal([]byte(line), &chunk) != nil {
			continue
		}
		if m := asString(chunk["model"]); m != "" && chat.Model == "" {
			chat.Model = m
		}
		if dr := asString(chunk["done_reason"]); dr != "" {
			chat.StopReason = dr
		}
		if r := asString(chunk["response"]); r != "" {
			textBuf.WriteString(r)
		}
		if th := asString(chunk["thinking"]); th != "" {
			thinkBuf.WriteString(th)
		}
		if msg, ok := chunk["message"].(map[string]any); ok {
			textBuf.WriteString(asString(msg["content"]))
			thinkBuf.WriteString(asString(msg["thinking"]))
			parsed := parseOpenAIMessage(msg)
			if len(parsed.ToolCalls) > 0 {
				chat.ToolCalls = append(chat.ToolCalls, parsed.ToolCalls...)
			}
		}
		if pe, ok := asFloat(chunk["prompt_eval_count"]); ok {
			chat.Usage.InputTokens = int(pe)
		}
		if ec, ok := asFloat(chunk["eval_count"]); ok {
			chat.Usage.OutputTokens = int(ec)
		}
	}
	chat.Usage.TotalTokens = chat.Usage.InputTokens + chat.Usage.OutputTokens
	chat.ResponseText = textBuf.String()
	chat.ReasoningText = thinkBuf.String()
	return chat, nil
}

package parser

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/model"
)

// ParseAnthropic parses Anthropic /v1/messages requests & responses (both JSON and SSE).
func ParseAnthropic(reqBody []byte, respBody []byte, isSSE bool) (*model.ChatSummary, error) {
	chat := &model.ChatSummary{}
	var req map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &req) == nil {
		chat.Model = asString(req["model"])
		if s, ok := req["stream"].(bool); ok {
			chat.IsStream = s
		}
		switch sys := req["system"].(type) {
		case string:
			chat.SystemPrompt = sys
		case []any:
			var sp []string
			for _, blk := range sys {
				if bm, ok := blk.(map[string]any); ok {
					if t := asString(bm["text"]); t != "" {
						sp = append(sp, t)
					}
				}
			}
			chat.SystemPrompt = strings.Join(sp, "\n")
		}
		if msgs, ok := req["messages"].([]any); ok {
			for _, rawMsg := range msgs {
				if m, ok := rawMsg.(map[string]any); ok {
					chat.Messages = append(chat.Messages, parseAnthropicMessage(m))
				}
			}
		}
	}
	if len(respBody) == 0 {
		return chat, nil
	}
	trimmedResp := bytes.TrimSpace(respBody)
	if isSSE || bytes.HasPrefix(trimmedResp, []byte("event:")) || bytes.HasPrefix(trimmedResp, []byte("data:")) {
		chat.IsStream = true
		parseAnthropicSSEResponse(respBody, chat)
		return chat, nil
	}
	var resp map[string]any
	if json.Unmarshal(respBody, &resp) == nil {
		if m := asString(resp["model"]); m != "" && chat.Model == "" {
			chat.Model = m
		}
		chat.StopReason = asString(resp["stop_reason"])
		parsed := parseAnthropicMessage(resp)
		chat.ResponseText = parsed.Content
		chat.ReasoningText = parsed.Thinking
		chat.ToolCalls = parsed.ToolCalls
		if usage, ok := resp["usage"].(map[string]any); ok {
			parseAnthropicUsage(usage, &chat.Usage)
		}
	}
	return chat, nil
}

func parseAnthropicMessage(m map[string]any) model.ChatMessage {
	cm := model.ChatMessage{Role: asString(m["role"])}
	switch content := m["content"].(type) {
	case string:
		cm.Content = content
	case []any:
		var texts []string
		var thoughts []string
		for _, blk := range content {
			bm, ok := blk.(map[string]any)
			if !ok {
				continue
			}
			switch asString(bm["type"]) {
			case "text":
				texts = append(texts, asString(bm["text"]))
			case "thinking":
				thoughts = append(thoughts, asString(bm["thinking"]))
			case "tool_use":
				argsBytes, _ := json.Marshal(bm["input"])
				cm.ToolCalls = append(cm.ToolCalls, model.ToolCallItem{
					ID:        asString(bm["id"]),
					Name:      asString(bm["name"]),
					Arguments: string(argsBytes),
				})
			case "tool_result":
				cm.ToolCallID = asString(bm["tool_use_id"])
				texts = append(texts, asString(bm["content"]))
			}
		}
		cm.Content = strings.Join(texts, "\n")
		cm.Thinking = strings.Join(thoughts, "\n")
	}
	return cm
}

func parseAnthropicSSEResponse(respBody []byte, chat *model.ChatSummary) {
	var textBuf strings.Builder
	var thinkBuf strings.Builder
	toolsByIdx := map[int]*model.ToolCallItem{}
	var idxs []int

	for _, line := range strings.Split(string(respBody), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		var ev map[string]any
		if json.Unmarshal([]byte(payload), &ev) != nil {
			continue
		}
		switch asString(ev["type"]) {
		case "message_start":
			if msg, ok := ev["message"].(map[string]any); ok {
				if m := asString(msg["model"]); m != "" && chat.Model == "" {
					chat.Model = m
				}
				if u, ok := msg["usage"].(map[string]any); ok {
					parseAnthropicUsage(u, &chat.Usage)
				}
			}
		case "content_block_start":
			idx := 0
			if fi, ok := asFloat(ev["index"]); ok {
				idx = int(fi)
			}
			if cb, ok := ev["content_block"].(map[string]any); ok && asString(cb["type"]) == "tool_use" {
				if _, exists := toolsByIdx[idx]; !exists {
					idxs = append(idxs, idx)
				}
				toolsByIdx[idx] = &model.ToolCallItem{
					ID:   asString(cb["id"]),
					Name: asString(cb["name"]),
				}
			}
		case "content_block_delta":
			idx := 0
			if fi, ok := asFloat(ev["index"]); ok {
				idx = int(fi)
			}
			if delta, ok := ev["delta"].(map[string]any); ok {
				switch asString(delta["type"]) {
				case "text_delta":
					textBuf.WriteString(asString(delta["text"]))
				case "thinking_delta":
					thinkBuf.WriteString(asString(delta["thinking"]))
				case "input_json_delta":
					if item, ok := toolsByIdx[idx]; ok {
						item.Arguments += asString(delta["partial_json"])
					}
				}
			}
		case "message_delta":
			if delta, ok := ev["delta"].(map[string]any); ok {
				if sr := asString(delta["stop_reason"]); sr != "" {
					chat.StopReason = sr
				}
			}
			if u, ok := ev["usage"].(map[string]any); ok {
				parseAnthropicUsage(u, &chat.Usage)
			}
		}
	}
	chat.ResponseText = textBuf.String()
	chat.ReasoningText = thinkBuf.String()
	sort.Ints(idxs)
	for _, idx := range idxs {
		if tc := toolsByIdx[idx]; tc != nil {
			chat.ToolCalls = append(chat.ToolCalls, *tc)
		}
	}
}

func parseAnthropicUsage(usage map[string]any, out *model.TokenUsage) {
	if v, ok := asFloat(usage["input_tokens"]); ok {
		out.InputTokens = int(v)
	}
	if v, ok := asFloat(usage["output_tokens"]); ok {
		out.OutputTokens = int(v)
	}
	if v, ok := asFloat(usage["cache_read_input_tokens"]); ok {
		out.CachedTokens = int(v)
	}
	out.TotalTokens = out.InputTokens + out.OutputTokens
}

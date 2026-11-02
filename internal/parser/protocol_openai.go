package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/model"
)

// ParseOpenAIChat parses an OpenAI-compatible /v1/chat/completions request and JSON/SSE response.
func ParseOpenAIChat(reqBody []byte, respBody []byte, isSSE bool) (*model.ChatSummary, error) {
	chat := &model.ChatSummary{}
	var req map[string]any
	var reqErr error
	if len(reqBody) > 0 {
		if err := json.Unmarshal(reqBody, &req); err != nil {
			reqErr = fmt.Errorf("unmarshal openai chat request: %w", err)
		}
	}
	chat.Model = asString(req["model"])
	if s, ok := req["stream"].(bool); ok {
		chat.IsStream = s
	}
	if msgs, ok := req["messages"].([]any); ok {
		for _, rawMsg := range msgs {
			m, ok := rawMsg.(map[string]any)
			if !ok {
				continue
			}
			cm := parseOpenAIMessage(m)
			if (cm.Role == "system" || cm.Role == "developer") && chat.SystemPrompt == "" {
				chat.SystemPrompt = cm.Content
			}
			chat.Messages = append(chat.Messages, cm)
		}
	}

	if len(respBody) == 0 {
		return chat, reqErr
	}
	trimmedResp := bytes.TrimSpace(respBody)
	if isSSE || bytes.HasPrefix(trimmedResp, []byte("data:")) || bytes.HasPrefix(trimmedResp, []byte("event:")) {
		chat.IsStream = true
		parseOpenAISSEResponse(respBody, chat)
		return chat, reqErr
	}

	var resp map[string]any
	if err := json.Unmarshal(respBody, &resp); err == nil {
		if m := asString(resp["model"]); m != "" && chat.Model == "" {
			chat.Model = m
		}
		if choices, ok := resp["choices"].([]any); ok && len(choices) > 0 {
			if c0, ok := choices[0].(map[string]any); ok {
				chat.StopReason = asString(c0["finish_reason"])
				if msg, ok := c0["message"].(map[string]any); ok {
					parsed := parseOpenAIMessage(msg)
					chat.ResponseText = parsed.Content
					chat.ReasoningText = parsed.Thinking
					chat.ToolCalls = parsed.ToolCalls
				}
			}
		}
		if usage, ok := resp["usage"].(map[string]any); ok {
			parseOpenAIUsage(usage, &chat.Usage)
		}
	}
	return chat, reqErr
}

func parseOpenAIMessage(m map[string]any) model.ChatMessage {
	thinking := asString(m["reasoning_content"])
	if thinking == "" {
		thinking = asString(m["reasoning"])
	}
	cm := model.ChatMessage{
		Role:       asString(m["role"]),
		Thinking:   thinking,
		ToolCallID: asString(m["tool_call_id"]),
	}
	switch content := m["content"].(type) {
	case string:
		cm.Content = content
	case []any:
		var parts []string
		for _, p := range content {
			if pm, ok := p.(map[string]any); ok {
				if txt := asString(pm["text"]); txt != "" {
					parts = append(parts, txt)
				} else if inputTxt := asString(pm["input_text"]); inputTxt != "" {
					parts = append(parts, inputTxt)
				}
			}
		}
		cm.Content = strings.Join(parts, "\n")
	}
	if tcs, ok := m["tool_calls"].([]any); ok {
		for _, rawTC := range tcs {
			if tcMap, ok := rawTC.(map[string]any); ok {
				tcItem := model.ToolCallItem{
					ID: asString(tcMap["id"]),
				}
				if fn, ok := tcMap["function"].(map[string]any); ok {
					tcItem.Name = asString(fn["name"])
					tcItem.Arguments = asString(fn["arguments"])
				}
				cm.ToolCalls = append(cm.ToolCalls, tcItem)
			}
		}
	}
	return cm
}

func parseOpenAISSEResponse(respBody []byte, chat *model.ChatSummary) {
	var textBuf strings.Builder
	var reasonBuf strings.Builder
	toolCallByIdx := map[int]*model.ToolCallItem{}
	var idxs []int

	lines := strings.Split(string(respBody), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var chunk map[string]any
		if json.Unmarshal([]byte(payload), &chunk) != nil {
			continue
		}
		if m := asString(chunk["model"]); m != "" && chat.Model == "" {
			chat.Model = m
		}
		if choices, ok := chunk["choices"].([]any); ok && len(choices) > 0 {
			if c0, ok := choices[0].(map[string]any); ok {
				if fr := asString(c0["finish_reason"]); fr != "" {
					chat.StopReason = fr
				}
				if delta, ok := c0["delta"].(map[string]any); ok {
					textBuf.WriteString(asString(delta["content"]))
					if rc := asString(delta["reasoning_content"]); rc != "" {
						reasonBuf.WriteString(rc)
					} else if r := asString(delta["reasoning"]); r != "" {
						reasonBuf.WriteString(r)
					}
					if tcs, ok := delta["tool_calls"].([]any); ok {
						for i, rawTC := range tcs {
							tcMap, ok := rawTC.(map[string]any)
							if !ok {
								continue
							}
							idx := i
							if fIdx, ok := asFloat(tcMap["index"]); ok {
								idx = int(fIdx)
							}
							item, exists := toolCallByIdx[idx]
							if !exists {
								item = &model.ToolCallItem{}
								toolCallByIdx[idx] = item
								idxs = append(idxs, idx)
							}
							if id := asString(tcMap["id"]); id != "" {
								item.ID = id
							}
							if fn, ok := tcMap["function"].(map[string]any); ok {
								if name := asString(fn["name"]); name != "" {
									item.Name += name
								}
								if args := asString(fn["arguments"]); args != "" {
									item.Arguments += args
								}
							}
						}
					}
				}
			}
		}
		if usage, ok := chunk["usage"].(map[string]any); ok {
			parseOpenAIUsage(usage, &chat.Usage)
		}
	}
	chat.ResponseText = textBuf.String()
	chat.ReasoningText = reasonBuf.String()
	sort.Ints(idxs)
	for _, idx := range idxs {
		chat.ToolCalls = append(chat.ToolCalls, *toolCallByIdx[idx])
	}
}

func parseOpenAIUsage(usage map[string]any, out *model.TokenUsage) {
	if v, ok := asFloat(usage["prompt_tokens"]); ok {
		out.InputTokens = int(v)
	} else if v, ok := asFloat(usage["input_tokens"]); ok {
		out.InputTokens = int(v)
	}
	if v, ok := asFloat(usage["completion_tokens"]); ok {
		out.OutputTokens = int(v)
	} else if v, ok := asFloat(usage["output_tokens"]); ok {
		out.OutputTokens = int(v)
	}
	if v, ok := asFloat(usage["total_tokens"]); ok {
		out.TotalTokens = int(v)
	} else {
		out.TotalTokens = out.InputTokens + out.OutputTokens
	}
	if details, ok := usage["completion_tokens_details"].(map[string]any); ok {
		if v, ok := asFloat(details["reasoning_tokens"]); ok {
			out.ReasoningTokens = int(v)
		}
	}
	if details, ok := usage["prompt_tokens_details"].(map[string]any); ok {
		if v, ok := asFloat(details["cached_tokens"]); ok {
			out.CachedTokens = int(v)
		}
	}
}

// ParseOpenAIResponses parses OpenAI /v1/responses requests & responses.
func ParseOpenAIResponses(reqBody []byte, respBody []byte, isSSE bool) (*model.ChatSummary, error) {
	chat := &model.ChatSummary{}
	var req map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &req) == nil {
		chat.Model = asString(req["model"])
		chat.SystemPrompt = asString(req["instructions"])
		if s, ok := req["stream"].(bool); ok {
			chat.IsStream = s
		}
		switch inp := req["input"].(type) {
		case string:
			chat.Messages = append(chat.Messages, model.ChatMessage{Role: "user", Content: inp})
		case []any:
			for _, item := range inp {
				if m, ok := item.(map[string]any); ok {
					itemType := asString(m["type"])
					switch itemType {
					case "function_call":
						callID := asString(m["call_id"])
						if callID == "" {
							callID = asString(m["id"])
						}
						chat.Messages = append(chat.Messages, model.ChatMessage{
							Role: "assistant",
							ToolCalls: []model.ToolCallItem{
								{
									ID:        callID,
									Name:      asString(m["name"]),
									Arguments: asString(m["arguments"]),
								},
							},
						})
						continue
					case "function_call_output":
						chat.Messages = append(chat.Messages, model.ChatMessage{
							Role:       "tool",
							ToolCallID: asString(m["call_id"]),
							Content:    asString(m["output"]),
						})
						continue
					}
					role := asString(m["role"])
					if role == "" {
						role = itemType
					}
					cm := parseOpenAIMessage(m)
					cm.Role = role
					chat.Messages = append(chat.Messages, cm)
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
		var textBuf strings.Builder
		var reasonBuf strings.Builder
		var toolCalls []model.ToolCallItem
		seenCallIDs := map[string]int{}

		addOrUpdateToolCall := func(tc model.ToolCallItem) {
			if tc.ID != "" {
				if idx, exists := seenCallIDs[tc.ID]; exists {
					if tc.Name != "" {
						toolCalls[idx].Name = tc.Name
					}
					if tc.Arguments != "" {
						toolCalls[idx].Arguments = tc.Arguments
					}
					return
				}
				seenCallIDs[tc.ID] = len(toolCalls)
			}
			toolCalls = append(toolCalls, tc)
		}

		for _, line := range strings.Split(string(respBody), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if payload == "" || payload == "[DONE]" {
				continue
			}
			var ev map[string]any
			if json.Unmarshal([]byte(payload), &ev) != nil {
				continue
			}
			switch asString(ev["type"]) {
			case "response.created":
				if rObj, ok := ev["response"].(map[string]any); ok {
					if m := asString(rObj["model"]); m != "" && chat.Model == "" {
						chat.Model = m
					}
				}
			case "response.output_text.delta":
				textBuf.WriteString(asString(ev["delta"]))
			case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
				reasonBuf.WriteString(asString(ev["delta"]))
			case "response.output_item.added", "response.output_item.done":
				if item, ok := ev["item"].(map[string]any); ok && asString(item["type"]) == "function_call" {
					callID := asString(item["call_id"])
					if callID == "" {
						callID = asString(item["id"])
					}
					addOrUpdateToolCall(model.ToolCallItem{
						ID:        callID,
						Name:      asString(item["name"]),
						Arguments: asString(item["arguments"]),
					})
				}
			case "response.completed":
				if rObj, ok := ev["response"].(map[string]any); ok {
					if m := asString(rObj["model"]); m != "" && chat.Model == "" {
						chat.Model = m
					}
					if st := asString(rObj["status"]); st != "" && chat.StopReason == "" {
						chat.StopReason = st
					}
					if outputs, ok := rObj["output"].([]any); ok {
						parseResponsesOutputItems(outputs, &textBuf, &reasonBuf, addOrUpdateToolCall)
					}
					if u, ok := rObj["usage"].(map[string]any); ok {
						parseOpenAIUsage(u, &chat.Usage)
					}
				}
			}
		}
		chat.ResponseText = textBuf.String()
		chat.ReasoningText = reasonBuf.String()
		chat.ToolCalls = toolCalls
		return chat, nil
	}
	var resp map[string]any
	if json.Unmarshal(respBody, &resp) == nil {
		if m := asString(resp["model"]); m != "" && chat.Model == "" {
			chat.Model = m
		}
		if st := asString(resp["status"]); st != "" {
			chat.StopReason = st
		}
		if outText := asString(resp["output_text"]); outText != "" {
			chat.ResponseText = outText
		}
		if outputs, ok := resp["output"].([]any); ok {
			var textBuf, reasonBuf strings.Builder
			parseResponsesOutputItems(outputs, &textBuf, &reasonBuf, func(tc model.ToolCallItem) {
				chat.ToolCalls = append(chat.ToolCalls, tc)
			})
			if chat.ResponseText == "" {
				chat.ResponseText = textBuf.String()
			}
			if chat.ReasoningText == "" {
				chat.ReasoningText = reasonBuf.String()
			}
		}
		if u, ok := resp["usage"].(map[string]any); ok {
			parseOpenAIUsage(u, &chat.Usage)
		}
	}
	return chat, nil
}

func parseResponsesOutputItems(outputs []any, textBuf *strings.Builder, reasonBuf *strings.Builder, onToolCall func(model.ToolCallItem)) {
	needTextFallback := textBuf.Len() == 0
	needReasonFallback := reasonBuf.Len() == 0
	var textParts, reasonParts []string
	for _, o := range outputs {
		om, ok := o.(map[string]any)
		if !ok {
			continue
		}
		switch asString(om["type"]) {
		case "function_call":
			callID := asString(om["call_id"])
			if callID == "" {
				callID = asString(om["id"])
			}
			onToolCall(model.ToolCallItem{
				ID:        callID,
				Name:      asString(om["name"]),
				Arguments: asString(om["arguments"]),
			})
		case "reasoning":
			if needReasonFallback {
				if summary, ok := om["summary"].([]any); ok {
					for _, s := range summary {
						if sm, ok := s.(map[string]any); ok {
							if t := asString(sm["text"]); t != "" {
								reasonParts = append(reasonParts, t)
							}
						}
					}
				}
			}
		default:
			if needTextFallback {
				if content, ok := om["content"].([]any); ok {
					for _, c := range content {
						if cm, ok := c.(map[string]any); ok {
							if t := asString(cm["text"]); t != "" {
								textParts = append(textParts, t)
							}
						}
					}
				}
			}
		}
	}
	if needTextFallback && len(textParts) > 0 {
		textBuf.WriteString(strings.Join(textParts, "\n"))
	}
	if needReasonFallback && len(reasonParts) > 0 {
		reasonBuf.WriteString(strings.Join(reasonParts, "\n"))
	}
}

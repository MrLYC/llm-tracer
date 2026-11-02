package parser

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/model"
)

// ParseGemini parses Google Gemini generateContent / streamGenerateContent payloads.
func ParseGemini(path string, reqBody []byte, respBody []byte, isSSE bool) (*model.ChatSummary, error) {
	chat := &model.ChatSummary{IsStream: isSSE}
	if idx := strings.Index(path, "/models/"); idx >= 0 {
		rest := path[idx+len("/models/"):]
		if colon := strings.Index(rest, ":"); colon > 0 {
			chat.Model = rest[:colon]
		}
	}
	var req map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &req) == nil {
		for _, sysKey := range []string{"systemInstruction", "system_instruction"} {
			if sysObj, ok := req[sysKey].(map[string]any); ok {
				if pList, ok := sysObj["parts"].([]any); ok {
					var sp []string
					for _, p := range pList {
						if pm, ok := p.(map[string]any); ok {
							if t := asString(pm["text"]); t != "" {
								sp = append(sp, t)
							}
						}
					}
					if len(sp) > 0 {
						chat.SystemPrompt = strings.Join(sp, "\n")
						break
					}
				}
			}
		}
		if contents, ok := req["contents"].([]any); ok {
			for _, c := range contents {
				if cm, ok := c.(map[string]any); ok {
					role := asString(cm["role"])
					if role == "" {
						role = "user"
					}
					var parts, thoughts []string
					var toolCalls []model.ToolCallItem
					var toolCallID string
					if pList, ok := cm["parts"].([]any); ok {
						for _, p := range pList {
							if pm, ok := p.(map[string]any); ok {
								isThought, _ := pm["thought"].(bool)
								if t := asString(pm["text"]); t != "" {
									if isThought {
										thoughts = append(thoughts, t)
									} else {
										parts = append(parts, t)
									}
								}
								if fc, ok := pm["functionCall"].(map[string]any); ok {
									argsBytes, _ := json.Marshal(fc["args"])
									name := asString(fc["name"])
									id := asString(fc["id"])
									if id == "" {
										id = name
									}
									toolCalls = append(toolCalls, model.ToolCallItem{
										ID:        id,
										Name:      name,
										Arguments: string(argsBytes),
									})
								}
								if fr, ok := pm["functionResponse"].(map[string]any); ok {
									name := asString(fr["name"])
									id := asString(fr["id"])
									if id == "" {
										id = name
									}
									toolCallID = id
									respBytes, _ := json.Marshal(fr["response"])
									parts = append(parts, string(respBytes))
								}
							}
						}
					}
					chat.Messages = append(chat.Messages, model.ChatMessage{
						Role:       role,
						Content:    strings.Join(parts, "\n"),
						Thinking:   strings.Join(thoughts, "\n"),
						ToolCalls:  toolCalls,
						ToolCallID: toolCallID,
					})
				}
			}
		}
	}
	if len(respBody) == 0 {
		return chat, nil
	}

	var textParts, thoughtParts []string
	consumeGeminiRespObj := func(resp map[string]any) {
		if mv := asString(resp["modelVersion"]); mv != "" && chat.Model == "" {
			chat.Model = mv
		}
		if cands, ok := resp["candidates"].([]any); ok && len(cands) > 0 {
			if c0, ok := cands[0].(map[string]any); ok {
				if fr := asString(c0["finishReason"]); fr != "" {
					chat.StopReason = fr
				}
				if content, ok := c0["content"].(map[string]any); ok {
					if parts, ok := content["parts"].([]any); ok {
						for _, p := range parts {
							pm, ok := p.(map[string]any)
							if !ok {
								continue
							}
							isThought, _ := pm["thought"].(bool)
							if t := asString(pm["text"]); t != "" {
								if isThought {
									thoughtParts = append(thoughtParts, t)
								} else {
									textParts = append(textParts, t)
								}
							}
							if fc, ok := pm["functionCall"].(map[string]any); ok {
								argsBytes, _ := json.Marshal(fc["args"])
								name := asString(fc["name"])
								id := asString(fc["id"])
								if id == "" {
									id = name
								}
								chat.ToolCalls = append(chat.ToolCalls, model.ToolCallItem{
									ID:        id,
									Name:      name,
									Arguments: string(argsBytes),
								})
							}
						}
					}
				}
			}
		}
		if u, ok := resp["usageMetadata"].(map[string]any); ok {
			if v, ok := asFloat(u["promptTokenCount"]); ok {
				chat.Usage.InputTokens = int(v)
			}
			if v, ok := asFloat(u["candidatesTokenCount"]); ok {
				chat.Usage.OutputTokens = int(v)
			}
			if v, ok := asFloat(u["thoughtsTokenCount"]); ok {
				chat.Usage.ReasoningTokens = int(v)
			}
			if v, ok := asFloat(u["cachedContentTokenCount"]); ok {
				chat.Usage.CachedTokens = int(v)
			}
			if v, ok := asFloat(u["totalTokenCount"]); ok {
				chat.Usage.TotalTokens = int(v)
			} else {
				chat.Usage.TotalTokens = chat.Usage.InputTokens + chat.Usage.OutputTokens
			}
		}
	}

	trimmed := bytes.TrimSpace(respBody)
	if isSSE || bytes.HasPrefix(trimmed, []byte("data:")) {
		chat.IsStream = true
		for _, line := range strings.Split(string(respBody), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			var chunk map[string]any
			if json.Unmarshal([]byte(payload), &chunk) == nil {
				consumeGeminiRespObj(chunk)
			}
		}
	} else {
		var resp map[string]any
		if json.Unmarshal(respBody, &resp) == nil {
			consumeGeminiRespObj(resp)
		}
	}
	chat.ResponseText = strings.Join(textParts, "")
	chat.ReasoningText = strings.Join(thoughtParts, "")
	return chat, nil
}

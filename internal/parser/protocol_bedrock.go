package parser

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/model"
)

// ParseBedrock parses AWS Bedrock Converse & Invoke API requests and responses.
func ParseBedrock(path string, reqBody []byte, respBody []byte) (*model.ChatSummary, error) {
	chat := &model.ChatSummary{}
	if idx := strings.Index(path, "/model/"); idx >= 0 {
		rest := path[idx+len("/model/"):]
		if slash := strings.IndexByte(rest, '/'); slash > 0 {
			rawModel := rest[:slash]
			if unescaped, err := url.PathUnescape(rawModel); err == nil {
				chat.Model = unescaped
			} else {
				chat.Model = rawModel
			}
		}
	}
	var req map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &req) == nil {
		if m := asString(req["modelId"]); m != "" && chat.Model == "" {
			chat.Model = m
		}
		if sysList, ok := req["system"].([]any); ok {
			var sp []string
			for _, s := range sysList {
				if sm, ok := s.(map[string]any); ok {
					if t := asString(sm["text"]); t != "" {
						sp = append(sp, t)
					}
				}
			}
			chat.SystemPrompt = strings.Join(sp, "\n")
		}
		if msgs, ok := req["messages"].([]any); ok {
			for _, rawMsg := range msgs {
				if m, ok := rawMsg.(map[string]any); ok {
					chat.Messages = append(chat.Messages, parseBedrockMessage(m))
				}
			}
		}
	}
	var resp map[string]any
	if len(respBody) > 0 && json.Unmarshal(respBody, &resp) == nil {
		chat.StopReason = asString(resp["stopReason"])
		if outObj, ok := resp["output"].(map[string]any); ok {
			if msgObj, ok := outObj["message"].(map[string]any); ok {
				parsed := parseBedrockMessage(msgObj)
				chat.ResponseText = parsed.Content
				chat.ReasoningText = parsed.Thinking
				chat.ToolCalls = parsed.ToolCalls
			}
		}
		if u, ok := resp["usage"].(map[string]any); ok {
			if v, ok := asFloat(u["inputTokens"]); ok {
				chat.Usage.InputTokens = int(v)
			}
			if v, ok := asFloat(u["outputTokens"]); ok {
				chat.Usage.OutputTokens = int(v)
			}
			if v, ok := asFloat(u["cacheReadInputTokens"]); ok {
				chat.Usage.CachedTokens = int(v)
			}
			if v, ok := asFloat(u["totalTokens"]); ok {
				chat.Usage.TotalTokens = int(v)
			} else {
				chat.Usage.TotalTokens = chat.Usage.InputTokens + chat.Usage.OutputTokens
			}
		}
	}
	return chat, nil
}

func parseBedrockMessage(m map[string]any) model.ChatMessage {
	cm := model.ChatMessage{Role: asString(m["role"])}
	if content, ok := m["content"].([]any); ok {
		var texts, thoughts []string
		for _, blk := range content {
			bm, ok := blk.(map[string]any)
			if !ok {
				continue
			}
			if t := asString(bm["text"]); t != "" {
				texts = append(texts, t)
			}
			if rc, ok := bm["reasoningContent"].(map[string]any); ok {
				if rt, ok := rc["reasoningText"].(map[string]any); ok {
					if t := asString(rt["text"]); t != "" {
						thoughts = append(thoughts, t)
					}
				}
			}
			if tu, ok := bm["toolUse"].(map[string]any); ok {
				argsBytes, _ := json.Marshal(tu["input"])
				cm.ToolCalls = append(cm.ToolCalls, model.ToolCallItem{
					ID:        asString(tu["toolUseId"]),
					Name:      asString(tu["name"]),
					Arguments: string(argsBytes),
				})
			}
			if tr, ok := bm["toolResult"].(map[string]any); ok {
				cm.ToolCallID = asString(tr["toolUseId"])
				if trContent, ok := tr["content"].([]any); ok {
					for _, item := range trContent {
						if im, ok := item.(map[string]any); ok {
							if t := asString(im["text"]); t != "" {
								texts = append(texts, t)
							} else if j, hasJ := im["json"]; hasJ {
								jb, _ := json.Marshal(j)
								texts = append(texts, string(jb))
							}
						}
					}
				}
			}
		}
		cm.Content = strings.Join(texts, "\n")
		cm.Thinking = strings.Join(thoughts, "\n")
	}
	return cm
}

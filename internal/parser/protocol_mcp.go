package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mrlyc/llm-tracer/internal/model"
)

// ParseMCP parses Model Context Protocol (MCP) JSON-RPC 2.0 requests and responses over HTTP/SSE.
func ParseMCP(path string, reqBody []byte, respBody []byte, isSSE bool) (*model.ChatSummary, error) {
	chat := &model.ChatSummary{IsStream: isSSE}
	var req map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &req) == nil {
		method := asString(req["method"])
		rpcID := fmt.Sprintf("%v", req["id"])
		chat.Model = "mcp:" + method
		params, _ := req["params"].(map[string]any)
		switch method {
		case "tools/call":
			toolName := asString(params["name"])
			argsBytes, _ := json.Marshal(params["arguments"])
			tc := model.ToolCallItem{
				ID:        rpcID,
				Name:      toolName,
				Arguments: string(argsBytes),
			}
			chat.ToolCalls = append(chat.ToolCalls, tc)
			chat.Messages = append(chat.Messages, model.ChatMessage{
				Role:      "user",
				Content:   fmt.Sprintf("tools/call %s %s", toolName, string(argsBytes)),
				ToolCalls: []model.ToolCallItem{tc},
			})
		default:
			pBytes, _ := json.Marshal(params)
			chat.Messages = append(chat.Messages, model.ChatMessage{
				Role:    "user",
				Content: fmt.Sprintf("%s %s", method, string(pBytes)),
			})
		}
	}
	if len(respBody) == 0 {
		return chat, nil
	}

	parseMCPRespObj := func(resp map[string]any) {
		if errObj, ok := resp["error"].(map[string]any); ok {
			chat.StopReason = "error"
			chat.ResponseText = asString(errObj["message"])
			return
		}
		resObj, ok := resp["result"].(map[string]any)
		if !ok {
			return
		}
		if isErr, _ := resObj["isError"].(bool); isErr {
			chat.StopReason = "error"
		} else {
			chat.StopReason = "ok"
		}
		if content, ok := resObj["content"].([]any); ok {
			var texts []string
			for _, c := range content {
				if cm, ok := c.(map[string]any); ok {
					if t := asString(cm["text"]); t != "" {
						texts = append(texts, t)
					}
				}
			}
			chat.ResponseText = strings.Join(texts, "\n")
			return
		}
		if tools, ok := resObj["tools"].([]any); ok {
			var names []string
			for _, t := range tools {
				if tm, ok := t.(map[string]any); ok {
					if n := asString(tm["name"]); n != "" {
						names = append(names, n)
					}
				}
			}
			chat.ResponseText = "tools: " + strings.Join(names, ", ")
			return
		}
		b, _ := json.Marshal(resObj)
		chat.ResponseText = string(b)
	}

	trimmed := bytes.TrimSpace(respBody)
	if isSSE || bytes.HasPrefix(trimmed, []byte("event:")) || bytes.HasPrefix(trimmed, []byte("data:")) {
		chat.IsStream = true
		for _, line := range strings.Split(string(respBody), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			var resp map[string]any
			if json.Unmarshal([]byte(payload), &resp) == nil {
				parseMCPRespObj(resp)
			}
		}
	} else {
		var resp map[string]any
		if json.Unmarshal(respBody, &resp) == nil {
			parseMCPRespObj(resp)
		}
	}
	return chat, nil
}

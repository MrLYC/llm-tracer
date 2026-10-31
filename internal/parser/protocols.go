package parser

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/liuyicong/llm-tracer/internal/model"
)

var targetQuestionMap = map[string]string{
	"CLICK":     "click_target",
	"TYPE_TEXT": "type_text_target",
	"SELECT":    "select_target",
	"DONE":      "done_target",
}

var sensitiveQueryKeys = map[string]bool{
	"key":          true,
	"api_key":      true,
	"apikey":       true,
	"token":        true,
	"access_token": true,
	"secret":       true,
	"sig":          true,
	"signature":    true,
	"auth":         true,
	"password":     true,
}

// RedactSensitivePath masks credential-like query parameters (such as ?key=AIza...) when headers/credentials are not recorded.
func RedactSensitivePath(rawPath string) string {
	qIdx := strings.IndexByte(rawPath, '?')
	if qIdx < 0 || qIdx == len(rawPath)-1 {
		return rawPath
	}
	base := rawPath[:qIdx]
	query := rawPath[qIdx+1:]
	parts := strings.Split(query, "&")
	changed := false
	for i, part := range parts {
		if part == "" {
			continue
		}
		k := part
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			k = part[:eq]
		}
		lk := strings.ToLower(strings.TrimSpace(k))
		if sensitiveQueryKeys[lk] {
			parts[i] = k + "=[REDACTED]"
			changed = true
		}
	}
	if !changed {
		return rawPath
	}
	return base + "?" + strings.Join(parts, "&")
}

// DetectProtocol determines the LLM protocol from URL path and JSON request/response payload.
func DetectProtocol(path string, reqBody []byte, respBody []byte) model.ProtocolType {
	lowerPath := strings.ToLower(path)
	switch {
	case strings.Contains(lowerPath, "/systemone"):
		return model.ProtocolSystemOne
	case strings.Contains(lowerPath, "/chat/completions"):
		return model.ProtocolOpenAIChat
	case strings.Contains(lowerPath, "/responses"):
		return model.ProtocolOpenAIResponses
	case strings.Contains(lowerPath, "/v1/messages") || strings.HasSuffix(lowerPath, "/messages"):
		return model.ProtocolAnthropic
	case strings.Contains(lowerPath, ":generatecontent") || strings.Contains(lowerPath, ":streamgeneratecontent"):
		return model.ProtocolGemini
	case strings.Contains(lowerPath, "/api/chat") || strings.Contains(lowerPath, "/api/generate"):
		return model.ProtocolOllama
	}

	// Fallback: inspect JSON structure
	var reqMap map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &reqMap) == nil {
		if _, hasQuestions := reqMap["questions"]; hasQuestions {
			if _, hasState := reqMap["state"]; hasState {
				return model.ProtocolSystemOne
			}
		}
		if _, hasContents := reqMap["contents"]; hasContents {
			return model.ProtocolGemini
		}
		if _, hasInput := reqMap["input"]; hasInput {
			if _, hasModel := reqMap["model"]; hasModel {
				return model.ProtocolOpenAIResponses
			}
		}
		if _, hasMsgs := reqMap["messages"]; hasMsgs {
			if _, hasAnthropicVer := reqMap["anthropic_version"]; hasAnthropicVer {
				return model.ProtocolAnthropic
			}
			if sysVal, hasSys := reqMap["system"]; hasSys && sysVal != nil {
				if _, hasMaxTokens := reqMap["max_tokens"]; hasMaxTokens {
					return model.ProtocolAnthropic
				}
			}
			return model.ProtocolOpenAIChat
		}
	}
	var respMap map[string]any
	if len(respBody) > 0 && json.Unmarshal(respBody, &respMap) == nil {
		if _, hasAnswers := respMap["answers"]; hasAnswers {
			return model.ProtocolSystemOne
		}
	}
	return model.ProtocolUnknown
}

// DecompressBody decodes gzip, deflate, or zstd HTTP payload bytes if needed.
func DecompressBody(raw []byte, contentEncoding string) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	enc := strings.ToLower(strings.TrimSpace(contentEncoding))
	if enc == "gzip" || (enc == "" && len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b) {
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw, err
		}
		defer gr.Close()
		out, err := io.ReadAll(gr)
		if err != nil {
			return raw, err
		}
		return out, nil
	}
	if enc == "deflate" {
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		out, err := io.ReadAll(fr)
		if err != nil {
			return raw, err
		}
		return out, nil
	}
	if enc == "zstd" {
		zr, err := zstd.NewReader(bytes.NewReader(raw))
		if err != nil {
			return raw, err
		}
		defer zr.Close()
		out, err := io.ReadAll(zr)
		if err != nil {
			return raw, err
		}
		return out, nil
	}
	return raw, nil
}

// ParseExchange enriches a TraceEvent from its raw request and response payloads.
func ParseExchange(ev *model.TraceEvent, reqBody []byte, respBody []byte, isSSE bool) error {
	proto := DetectProtocol(ev.Path, reqBody, respBody)
	if ev.Protocol == "" || ev.Protocol == model.ProtocolUnknown {
		ev.Protocol = proto
	}
	if !ev.HeadersRecorded {
		ev.RequestHeaders = nil
		ev.ResponseHeaders = nil
		ev.Path = RedactSensitivePath(ev.Path)
		if ev.Host != "" {
			ev.URL = fmt.Sprintf("https://%s%s", ev.Host, ev.Path)
		}
	}
	ev.RequestRaw = truncateString(string(reqBody), 256*1024)
	ev.ResponseRaw = truncateString(string(respBody), 256*1024)

	switch ev.Protocol {
	case model.ProtocolSystemOne:
		s1, err := ParseSystemOne(reqBody, respBody)
		ev.SystemOne = s1
		return err
	case model.ProtocolOpenAIChat:
		chat, err := ParseOpenAIChat(reqBody, respBody, isSSE)
		ev.Chat = chat
		return err
	case model.ProtocolOpenAIResponses:
		chat, err := ParseOpenAIResponses(reqBody, respBody, isSSE)
		ev.Chat = chat
		return err
	case model.ProtocolAnthropic:
		chat, err := ParseAnthropic(reqBody, respBody, isSSE)
		ev.Chat = chat
		return err
	case model.ProtocolGemini:
		chat, err := ParseGemini(ev.Path, reqBody, respBody, isSSE)
		ev.Chat = chat
		return err
	case model.ProtocolOllama:
		chat, err := ParseOllama(reqBody, respBody)
		ev.Chat = chat
		return err
	default:
		return nil
	}
}

// ParseSystemOne parses a TypeSafe JEV /systemone request and response.
func ParseSystemOne(reqBody []byte, respBody []byte) (*model.SystemOneStepSummary, error) {
	summary := &model.SystemOneStepSummary{}
	var req map[string]any
	if len(reqBody) > 0 {
		if err := json.Unmarshal(reqBody, &req); err != nil {
			return summary, fmt.Errorf("unmarshal systemone request: %w", err)
		}
	}
	summary.Model = asString(req["model"])

	// Extract state
	elementsByIdx := map[string]string{}
	if state, ok := req["state"].(map[string]any); ok {
		if page, ok := state["page"].(map[string]any); ok {
			summary.Page.URL = asString(page["url"])
			summary.Page.Title = asString(page["title"])
			fullText := asString(page["text"])
			summary.Page.TextLen = len(fullText)
			summary.Page.TextSnippet = truncateString(fullText, 400)
		}
		if elems, ok := state["elements"].([]any); ok {
			summary.Page.ElementCount = len(elems)
			for _, rawEl := range elems {
				if elMap, ok := rawEl.(map[string]any); ok {
					idx := asString(elMap["index"])
					lbl := asString(elMap["label"])
					if idx != "" {
						elementsByIdx[idx] = lbl
					}
				}
			}
		}
		if recent, ok := state["recent_actions"].([]any); ok {
			summary.RecentActionCount = len(recent)
			for _, item := range recent {
				if m, ok := item.(map[string]any); ok {
					summary.RecentActions = append(summary.RecentActions, m)
				}
			}
		}
	}

	// Extract answers from response first so we can merge them into questions
	answersMap := map[string]map[string]any{}
	var resp map[string]any
	if len(respBody) > 0 && json.Unmarshal(respBody, &resp) == nil {
		if respModel := asString(resp["model"]); respModel != "" && summary.Model == "" {
			summary.Model = respModel
		}
		if ansObj, ok := resp["answers"].(map[string]any); ok {
			for qid, rawAns := range ansObj {
				if am, ok := rawAns.(map[string]any); ok {
					answersMap[qid] = am
				}
			}
		}
	}

	// Extract questions in deterministic order (operation first, then targets, then text/others)
	if qMap, ok := req["questions"].(map[string]any); ok {
		qKeys := make([]string, 0, len(qMap))
		for k := range qMap {
			qKeys = append(qKeys, k)
		}
		sort.Slice(qKeys, func(i, j int) bool {
			return questionRank(qKeys[i]) < questionRank(qKeys[j])
		})

		for _, qid := range qKeys {
			rawQ, ok := qMap[qid].(map[string]any)
			if !ok {
				continue
			}
			qItem := model.SystemOneQuestion{
				ID:      qid,
				Type:    asString(rawQ["type"]),
				Options: make(map[string]string),
				Probs:   make(map[string]float64),
			}
			if instr, ok := rawQ["instructions"].(map[string]any); ok {
				qItem.Goal = asString(instr["goal"])
				if summary.Goal == "" && qItem.Goal != "" {
					summary.Goal = qItem.Goal
				}
				qItem.Operation = asString(instr["operation"])
				if guides, ok := instr["guide"].([]any); ok {
					for _, g := range guides {
						if gs := asString(g); gs != "" {
							qItem.Guides = append(qItem.Guides, gs)
						}
					}
				}
			}
			switch crit := rawQ["criteria"].(type) {
			case map[string]any:
				keys := make([]string, 0, len(crit))
				for k := range crit {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				qItem.OptionOrder = keys
				for _, k := range keys {
					v := crit[k]
					switch vm := v.(type) {
					case string:
						qItem.Options[k] = vm
					case map[string]any:
						elDesc := asString(vm["element"])
						if href := asString(vm["href"]); href != "" {
							elDesc += " (" + href + ")"
						}
						qItem.Options[k] = elDesc
					default:
						b, _ := json.Marshal(v)
						qItem.Options[k] = string(b)
					}
				}
			case []any:
				for _, item := range crit {
					s := asString(item)
					qItem.OptionOrder = append(qItem.OptionOrder, s)
					qItem.Options[s] = s
				}
			}

			if ans, ok := answersMap[qid]; ok {
				if ch, ok := ans["choice"].(string); ok {
					qItem.AnswerChoice = ch
				}
				if conf, ok := asFloat(ans["confidence"]); ok {
					qItem.Confidence = conf
				}
				if probs, ok := ans["probabilities"].(map[string]any); ok {
					bestKey := ""
					bestProb := -1.0
					for pk, pv := range probs {
						if pf, ok := asFloat(pv); ok {
							qItem.Probs[pk] = pf
							if pf > bestProb {
								bestProb = pf
								bestKey = pk
							}
						}
					}
					if qItem.AnswerChoice != "" {
						qItem.TopChoice = qItem.AnswerChoice
					} else if bestKey != "" {
						qItem.TopChoice = bestKey
						qItem.UsedArgmax = true
					}
				}
			}
			summary.Questions = append(summary.Questions, qItem)
		}
	}

	// Populate high-level step decision summary
	qByID := make(map[string]model.SystemOneQuestion, len(summary.Questions))
	for _, q := range summary.Questions {
		qByID[q.ID] = q
	}
	var fallbacks []string
	if opQ, ok := qByID["operation"]; ok && opQ.TopChoice != "" {
		summary.SelectedOp = opQ.TopChoice
		summary.OpConfidence = opQ.Confidence
		summary.QuestionsUsed = append(summary.QuestionsUsed, "operation")
		if opQ.UsedArgmax {
			fallbacks = append(fallbacks, fmt.Sprintf("operation choice was null; used argmax %s", opQ.TopChoice))
		}
		if targetQID, hasTarget := targetQuestionMap[summary.SelectedOp]; hasTarget {
			if tq, ok := qByID[targetQID]; ok && tq.TopChoice != "" {
				summary.SelectedTarget = tq.TopChoice
				summary.TargetConfidence = tq.Confidence
				summary.QuestionsUsed = append(summary.QuestionsUsed, targetQID)
				if desc, ok := tq.Options[tq.TopChoice]; ok && desc != "" {
					summary.SelectedElement = desc
				} else {
					baseIdx := strings.Split(tq.TopChoice, ":")[0]
					if lbl, ok := elementsByIdx[baseIdx]; ok {
						summary.SelectedElement = fmt.Sprintf("[%s] %s", baseIdx, lbl)
					}
				}
				if tq.UsedArgmax {
					fallbacks = append(fallbacks, fmt.Sprintf("%s choice was null; used argmax %s", targetQID, tq.TopChoice))
				}
			}
		}
		if summary.SelectedOp == "TYPE_TEXT" {
			if textQ, ok := qByID["text"]; ok && textQ.TopChoice != "" {
				summary.SelectedText = textQ.TopChoice
				summary.QuestionsUsed = append(summary.QuestionsUsed, "text")
				if textQ.UsedArgmax {
					fallbacks = append(fallbacks, fmt.Sprintf("text choice was null; used argmax %q", textQ.TopChoice))
				}
			}
		}
	}
	if len(fallbacks) > 0 {
		summary.FallbackReason = strings.Join(fallbacks, "; ")
	}
	return summary, nil
}

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
			if cm.Role == "system" && chat.SystemPrompt == "" {
				chat.SystemPrompt = cm.Content
			}
			chat.Messages = append(chat.Messages, cm)
		}
	}

	if len(respBody) == 0 {
		return chat, reqErr
	}
	if isSSE || bytes.HasPrefix(bytes.TrimSpace(respBody), []byte("data:")) || bytes.HasPrefix(bytes.TrimSpace(respBody), []byte("event:")) {
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
	cm := model.ChatMessage{
		Role:       asString(m["role"]),
		Thinking:   asString(m["reasoning_content"]),
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
					reasonBuf.WriteString(asString(delta["reasoning_content"]))
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
					role := asString(m["role"])
					if role == "" {
						role = asString(m["type"])
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
	if isSSE || bytes.HasPrefix(bytes.TrimSpace(respBody), []byte("event:")) || bytes.HasPrefix(bytes.TrimSpace(respBody), []byte("data:")) {
		chat.IsStream = true
		var textBuf strings.Builder
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
			case "response.output_text.delta":
				textBuf.WriteString(asString(ev["delta"]))
			case "response.completed":
				if rObj, ok := ev["response"].(map[string]any); ok {
					if u, ok := rObj["usage"].(map[string]any); ok {
						parseOpenAIUsage(u, &chat.Usage)
					}
				}
			}
		}
		chat.ResponseText = textBuf.String()
		return chat, nil
	}
	var resp map[string]any
	if json.Unmarshal(respBody, &resp) == nil {
		if outText := asString(resp["output_text"]); outText != "" {
			chat.ResponseText = outText
		} else if outputs, ok := resp["output"].([]any); ok {
			var parts []string
			for _, o := range outputs {
				if om, ok := o.(map[string]any); ok {
					if content, ok := om["content"].([]any); ok {
						for _, c := range content {
							if cm, ok := c.(map[string]any); ok {
								if t := asString(cm["text"]); t != "" {
									parts = append(parts, t)
								}
							}
						}
					}
				}
			}
			chat.ResponseText = strings.Join(parts, "\n")
		}
		if u, ok := resp["usage"].(map[string]any); ok {
			parseOpenAIUsage(u, &chat.Usage)
		}
	}
	return chat, nil
}

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
	if isSSE || bytes.HasPrefix(bytes.TrimSpace(respBody), []byte("event:")) || bytes.HasPrefix(bytes.TrimSpace(respBody), []byte("data:")) {
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
				toolsByIdx[idx] = &model.ToolCallItem{
					ID:   asString(cb["id"]),
					Name: asString(cb["name"]),
				}
				idxs = append(idxs, idx)
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
		chat.ToolCalls = append(chat.ToolCalls, *toolsByIdx[idx])
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
		if contents, ok := req["contents"].([]any); ok {
			for _, c := range contents {
				if cm, ok := c.(map[string]any); ok {
					role := asString(cm["role"])
					if role == "" {
						role = "user"
					}
					var parts []string
					if pList, ok := cm["parts"].([]any); ok {
						for _, p := range pList {
							if pm, ok := p.(map[string]any); ok {
								if t := asString(pm["text"]); t != "" {
									parts = append(parts, t)
								}
							}
						}
					}
					chat.Messages = append(chat.Messages, model.ChatMessage{
						Role:    role,
						Content: strings.Join(parts, "\n"),
					})
				}
			}
		}
	}
	var resp map[string]any
	if len(respBody) > 0 && json.Unmarshal(respBody, &resp) == nil {
		if cands, ok := resp["candidates"].([]any); ok && len(cands) > 0 {
			if c0, ok := cands[0].(map[string]any); ok {
				if content, ok := c0["content"].(map[string]any); ok {
					if parts, ok := content["parts"].([]any); ok {
						var texts []string
						for _, p := range parts {
							if pm, ok := p.(map[string]any); ok {
								if t := asString(pm["text"]); t != "" {
									texts = append(texts, t)
								}
							}
						}
						chat.ResponseText = strings.Join(texts, "\n")
					}
				}
			}
		}
	}
	return chat, nil
}

// ParseOllama parses Ollama /api/chat and /api/generate payloads.
func ParseOllama(reqBody []byte, respBody []byte) (*model.ChatSummary, error) {
	chat := &model.ChatSummary{}
	var req map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &req) == nil {
		chat.Model = asString(req["model"])
		if prompt := asString(req["prompt"]); prompt != "" {
			chat.Messages = append(chat.Messages, model.ChatMessage{Role: "user", Content: prompt})
		}
		if msgs, ok := req["messages"].([]any); ok {
			for _, m := range msgs {
				if mm, ok := m.(map[string]any); ok {
					chat.Messages = append(chat.Messages, parseOpenAIMessage(mm))
				}
			}
		}
	}
	var textBuf strings.Builder
	for _, line := range strings.Split(string(respBody), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var chunk map[string]any
		if json.Unmarshal([]byte(line), &chunk) != nil {
			continue
		}
		if r := asString(chunk["response"]); r != "" {
			textBuf.WriteString(r)
		}
		if msg, ok := chunk["message"].(map[string]any); ok {
			textBuf.WriteString(asString(msg["content"]))
		}
	}
	chat.ResponseText = textBuf.String()
	return chat, nil
}

func questionRank(qid string) int {
	switch qid {
	case "operation":
		return 0
	case "click_target":
		return 1
	case "type_text_target":
		return 2
	case "select_target":
		return 3
	case "done_target":
		return 4
	case "text":
		return 5
	default:
		return 10
	}
}

func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case fmt.Stringer:
		return s.String()
	default:
		return ""
	}
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

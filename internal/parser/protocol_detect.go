package parser

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

// MaxDecompressedBodyBytes caps decompressed HTTP payloads to prevent zip/zstd memory bombs.
const MaxDecompressedBodyBytes = 16 * 1024 * 1024

var sensitiveQueryKeys = selfmon.SensitiveQueryKeys

// RedactSensitivePath masks credential-like query parameters (such as ?key=AIza...) when headers/credentials are not recorded.
func RedactSensitivePath(rawPath string) string {
	if rawPath == "" {
		return rawPath
	}
	qIdx := strings.IndexByte(rawPath, '?')
	if qIdx < 0 {
		return selfmon.RedactPathMatrixParams(rawPath)
	}
	base := selfmon.RedactPathMatrixParams(rawPath[:qIdx])
	if qIdx == len(rawPath)-1 {
		return base + "?"
	}
	query := rawPath[qIdx+1:]
	return base + "?" + selfmon.RedactQueryPairs(query)
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
	case strings.Contains(lowerPath, "/model/") && (strings.Contains(lowerPath, "/converse") || strings.Contains(lowerPath, "/invoke")):
		return model.ProtocolBedrock
	case strings.HasSuffix(lowerPath, "/mcp") || strings.Contains(lowerPath, "/mcp/") || strings.Contains(lowerPath, "/mcp?"):
		return model.ProtocolMCP
	}

	// Fallback: inspect JSON structure
	var reqMap map[string]any
	if len(reqBody) > 0 && json.Unmarshal(reqBody, &reqMap) == nil {
		if asString(reqMap["jsonrpc"]) == "2.0" {
			m := asString(reqMap["method"])
			if strings.HasPrefix(m, "tools/") || strings.HasPrefix(m, "resources/") || strings.HasPrefix(m, "prompts/") ||
				strings.HasPrefix(m, "sampling/") || strings.HasPrefix(m, "notifications/") || m == "initialize" || m == "ping" {
				return model.ProtocolMCP
			}
		}
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
			if _, hasInfCfg := reqMap["inferenceConfig"]; hasInfCfg {
				return model.ProtocolBedrock
			}
			if _, hasToolCfg := reqMap["toolConfig"]; hasToolCfg {
				return model.ProtocolBedrock
			}
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

func readBounded(r io.Reader, limit int) ([]byte, error) {
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if len(out) > limit {
		return out[:limit], fmt.Errorf("decompressed body exceeded %d bytes", limit)
	}
	return out, err
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
		out, err := readBounded(gr, MaxDecompressedBodyBytes)
		if err != nil {
			return raw, err
		}
		return out, nil
	}
	if enc == "deflate" {
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		out, err := readBounded(fr, MaxDecompressedBodyBytes)
		if err != nil {
			return raw, err
		}
		return out, nil
	}
	if enc == "zstd" {
		zr, err := zstd.NewReader(
			bytes.NewReader(raw),
			zstd.WithDecoderMaxMemory(uint64(MaxDecompressedBodyBytes)),
			zstd.WithDecoderConcurrency(1),
		)
		if err != nil {
			return raw, err
		}
		defer zr.Close()
		out, err := readBounded(zr, MaxDecompressedBodyBytes)
		if err != nil {
			return raw, err
		}
		return out, nil
	}
	return raw, nil
}

// ParseExchange enriches a TraceEvent from its raw request and response payloads.
func ParseExchange(ev *model.TraceEvent, reqBody []byte, respBody []byte, isSSE bool) error {
	if ev == nil {
		return nil
	}
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
	ev.RequestRaw = truncateBytesToString(reqBody, 256*1024)
	ev.ResponseRaw = truncateBytesToString(respBody, 256*1024)

	switch ev.Protocol {
	case model.ProtocolSystemOne:
		s1, err := ParseSystemOne(reqBody, respBody)
		ev.SystemOne = s1
		return err
	case model.ProtocolOpenAIChat:
		chat, err := ParseOpenAIChat(reqBody, respBody, isSSE)
		if chat != nil && chat.Model == "" {
			chat.Model = extractAzureDeploymentModel(ev.Path)
		}
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
	case model.ProtocolBedrock:
		chat, err := ParseBedrock(ev.Path, reqBody, respBody)
		ev.Chat = chat
		return err
	case model.ProtocolMCP:
		chat, err := ParseMCP(ev.Path, reqBody, respBody, isSSE)
		ev.Chat = chat
		return err
	default:
		return nil
	}
}

func extractAzureDeploymentModel(path string) string {
	const marker = "/deployments/"
	idx := indexASCIIFold(path, marker)
	if idx < 0 {
		return ""
	}
	rest := path[idx+len(marker):]
	if slash := strings.IndexByte(rest, '/'); slash > 0 {
		return rest[:slash]
	}
	return ""
}

func indexASCIIFold(s, needleLower string) int {
	n := len(needleLower)
	if n == 0 || len(s) < n {
		return -1
	}
	for i := 0; i <= len(s)-n; i++ {
		match := true
		for j := 0; j < n; j++ {
			c := s[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needleLower[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
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

func truncateBytesToString(b []byte, maxLen int) string {
	if len(b) > maxLen {
		b = b[:maxLen]
	}
	return string(b)
}

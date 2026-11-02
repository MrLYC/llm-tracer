package parser

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

var correlationHintHeaderKeys = map[string]struct{}{
	"x-session-id":              {},
	"x-conversation-id":         {},
	"x-thread-id":               {},
	"openai-conversation-id":    {},
	"mcp-session-id":            {},
	"x-claude-session-id":       {},
	"x-codex-session-id":        {},
	"x-agent-session-id":        {},
	"x-langsmith-trace-id":      {},
	"x-request-session-id":      {},
	"anthropic-beta-session-id": {},
}

func extractCorrelationHintsFromHeader(getHeader func(string) string) []string {
	var hints []string
	if traceparent := strings.TrimSpace(getHeader("traceparent")); traceparent != "" {
		if traceID, ok := parseW3CTraceID(traceparent); ok {
			hints = append(hints, "w3c_trace:"+hashCorrelationValue(traceID))
		}
	}
	// Fixed order keeps generated hints deterministic despite Go map iteration.
	keys := []string{
		"x-session-id", "x-conversation-id", "x-thread-id", "openai-conversation-id",
		"mcp-session-id", "x-claude-session-id", "x-codex-session-id", "x-agent-session-id",
		"x-langsmith-trace-id", "x-request-session-id", "anthropic-beta-session-id",
	}
	for _, key := range keys {
		value := strings.TrimSpace(getHeader(key))
		if value == "" {
			continue
		}
		hints = append(hints, "hdr:"+key+":"+hashCorrelationValue(value))
	}
	return hints
}

func parseW3CTraceID(traceparent string) (string, bool) {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return "", false
	}
	version, traceID := parts[0], parts[1]
	if len(version) != 2 || len(traceID) != 32 || !isHexString(traceID) {
		return "", false
	}
	allZero := true
	for _, c := range traceID {
		if c != '0' {
			allZero = false
			break
		}
	}
	if allZero {
		return "", false
	}
	return traceID, true
}

func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func hashCorrelationValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

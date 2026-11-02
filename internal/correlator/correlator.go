package correlator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
)

type sessionTrack struct {
	sessionID       string
	explicitKeys    map[string]bool
	goal            string
	rootPID         int
	pids            map[int]bool
	connKeys        map[string]bool
	tids            map[int]bool
	cwd             string
	lastEventID     string
	lastStepEventID string
	lastUpdatedAt   int64
	stepCount       int
	turnCount       int
	eventStateByID  map[string]eventSlot
	msgSnapshots    []msgSnapshot
}

type eventSlot struct {
	sessionID   string
	parentID    string
	stepIndex   int
	turnIndex   int
	level       string
	reason      string
	prefixCount int
}

type msgSnapshot struct {
	eventID           string
	turnIndex         int
	reqHashes         []string
	fullHashes        []string // reqHashes + assistant response hash
	leadingSystem     int
	nonSystemMessages int
	lastMessageLength int
}

type Correlator struct {
	mu           sync.Mutex
	sessions     map[string]*sessionTrack
	explicitIdx  map[string]string // explicit key -> sessionID
	eventToSess  map[string]eventSlot
	activeWindow time.Duration
	mon          *selfmon.Monitor
}

func NewCorrelator(mon *selfmon.Monitor) *Correlator {
	return &Correlator{
		sessions:     make(map[string]*sessionTrack),
		explicitIdx:  make(map[string]string),
		eventToSess:  make(map[string]eventSlot),
		activeWindow: 15 * time.Minute,
		mon:          mon,
	}
}

// Correlate assigns SessionID, ParentEventID, StepIndex/TurnIndex, and Chat.NewMessages/PrefixCount.
func (c *Correlator) Correlate(ev *model.TraceEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ev.Timestamp == 0 {
		ev.Timestamp = time.Now().UnixMilli()
	}
	if len(c.sessions) > 512 || len(c.eventToSess) > 4096 {
		c.pruneStaleLocked(ev.Timestamp)
	}

	// Check if this is an in-place update for an already correlated streaming event
	if slot, exists := c.eventToSess[ev.ID]; exists {
		ev.SessionID = slot.sessionID
		ev.ParentEventID = slot.parentID
		ev.StepIndex = slot.stepIndex
		ev.TurnIndex = slot.turnIndex
		ev.CorrelationLevel = slot.level
		ev.CorrelationReason = slot.reason
		if ev.Chat != nil {
			ev.Chat.PrefixCount = slot.prefixCount
			if slot.prefixCount >= 0 && slot.prefixCount <= len(ev.Chat.Messages) {
				ev.Chat.NewMessages = ev.Chat.Messages[slot.prefixCount:]
			}
		}
		if st, ok := c.sessions[slot.sessionID]; ok {
			st.lastUpdatedAt = ev.Timestamp
			c.recordSessionMembershipLocked(st, ev)
			if respID := extractResponseObjectID(ev.ResponseRaw); respID != "" {
				c.explicitIdx["resp:"+respID] = st.sessionID
			}
			if ev.Status != "streaming" && ev.Chat != nil {
				c.recordChatSnapshotLocked(st, ev)
			}
		}
		return
	}

	explicitKeys, parentRespID := extractExplicitSessionKeys(ev)
	explicitKeys = append(explicitKeys, ev.CorrelationHints...)
	var matched *sessionTrack
	var corrLevel, corrReason, parentID string
	var prefixCount int

	// L1: Explicit Session / Conversation / Previous-Response ID
	if parentRespID != "" {
		if sid, ok := c.explicitIdx["resp:"+parentRespID]; ok {
			matched = c.sessions[sid]
			corrLevel = "L1_explicit"
			corrReason = "previous_response_id=" + parentRespID
		}
	}
	if matched == nil {
		for _, k := range explicitKeys {
			if sid, ok := c.explicitIdx[k]; ok {
				matched = c.sessions[sid]
				corrLevel = "L1_explicit"
				corrReason = k
				break
			}
		}
	}

	// L2: Context Evolution (SystemOne Goal+RecentActions OR Chat Messages Prefix Hash)
	if matched == nil {
		if ev.Protocol == model.ProtocolSystemOne && ev.SystemOne != nil && ev.SystemOne.Goal != "" {
			matched, parentID, corrReason = c.matchSystemOneLocked(ev)
			if matched != nil {
				corrLevel = "L2_context"
			}
		} else if ev.Chat != nil && len(ev.Chat.Messages) > 0 {
			matched, parentID, prefixCount, corrReason = c.matchChatPrefixLocked(ev)
			if matched != nil {
				corrLevel = "L2_context"
			}
		}
	}

	// L3: Process Tree + Active Time Window (e.g. JEV step calling helper LLM for TYPE_TEXT)
	if matched == nil && len(explicitKeys) == 0 && parentRespID == "" {
		matched, parentID, corrReason = c.matchProcessTreeLocked(ev)
		if matched != nil {
			corrLevel = "L3_proctree"
		}
	}

	// Create new session if no correlation matched
	if matched == nil {
		sid := "sess_" + strings.ReplaceAll(uuid.NewString()[:12], "-", "")
		matched = &sessionTrack{
			sessionID:      sid,
			explicitKeys:   make(map[string]bool),
			rootPID:        ev.Process.PID,
			pids:           make(map[int]bool),
			connKeys:       make(map[string]bool),
			tids:           make(map[int]bool),
			cwd:            ev.Process.Cwd,
			lastUpdatedAt:  ev.Timestamp,
			eventStateByID: make(map[string]eventSlot),
		}
		if ev.SystemOne != nil && ev.SystemOne.Goal != "" {
			matched.goal = ev.SystemOne.Goal
		}
		c.sessions[sid] = matched
		corrLevel = "root"
		corrReason = "new_session"
	}

	// Register explicit keys & PIDs on the session
	for _, k := range explicitKeys {
		matched.explicitKeys[k] = true
		c.explicitIdx[k] = matched.sessionID
	}
	if respID := extractResponseObjectID(ev.ResponseRaw); respID != "" {
		c.explicitIdx["resp:"+respID] = matched.sessionID
	}
	c.recordSessionMembershipLocked(matched, ev)
	if matched.cwd == "" && ev.Process.Cwd != "" {
		matched.cwd = ev.Process.Cwd
	}
	if matched.goal == "" && ev.SystemOne != nil && ev.SystemOne.Goal != "" {
		matched.goal = ev.SystemOne.Goal
	}

	if parentID == "" && matched.lastEventID != "" {
		parentID = matched.lastEventID
	}

	if ev.Protocol == model.ProtocolSystemOne {
		matched.stepCount++
		ev.StepIndex = matched.stepCount
		matched.lastStepEventID = ev.ID
	} else {
		matched.turnCount++
		ev.TurnIndex = matched.turnCount
		if matched.stepCount > 0 {
			ev.StepIndex = matched.stepCount
		}
	}

	ev.SessionID = matched.sessionID
	ev.ParentEventID = parentID
	ev.CorrelationLevel = corrLevel
	ev.CorrelationReason = corrReason

	if ev.Chat != nil {
		ev.Chat.PrefixCount = prefixCount
		if prefixCount >= 0 && prefixCount <= len(ev.Chat.Messages) {
			ev.Chat.NewMessages = ev.Chat.Messages[prefixCount:]
		} else {
			ev.Chat.NewMessages = ev.Chat.Messages
		}
		if ev.Status != "streaming" {
			c.recordChatSnapshotLocked(matched, ev)
		}
	}

	matched.lastEventID = ev.ID
	matched.lastUpdatedAt = ev.Timestamp

	slot := eventSlot{
		sessionID:   ev.SessionID,
		parentID:    ev.ParentEventID,
		stepIndex:   ev.StepIndex,
		turnIndex:   ev.TurnIndex,
		level:       ev.CorrelationLevel,
		reason:      ev.CorrelationReason,
		prefixCount: prefixCount,
	}
	matched.eventStateByID[ev.ID] = slot
	c.eventToSess[ev.ID] = slot

	if c.mon != nil {
		c.mon.Record(selfmon.Event{
			Status:    selfmon.StatusOK,
			Stage:     selfmon.StageCorrelator,
			Action:    "correlate_" + corrLevel,
			PID:       ev.Process.PID,
			Comm:      ev.Process.Comm,
			SessionID: ev.SessionID,
			Detail: map[string]any{
				"event_id":  ev.ID,
				"protocol":  ev.Protocol,
				"reason":    corrReason,
				"step":      ev.StepIndex,
				"turn":      ev.TurnIndex,
				"parent_id": ev.ParentEventID,
			},
		})
	}
}

func (c *Correlator) pruneStaleLocked(nowMs int64) {
	ttlMs := (2 * c.activeWindow).Milliseconds()
	if ttlMs <= 0 {
		ttlMs = (30 * time.Minute).Milliseconds()
	}
	cutoff := nowMs - ttlMs
	for sid, st := range c.sessions {
		if st.lastUpdatedAt < cutoff {
			for k := range st.explicitKeys {
				delete(c.explicitIdx, k)
			}
			for eid := range st.eventStateByID {
				delete(c.eventToSess, eid)
			}
			delete(c.sessions, sid)
		}
	}
}

func (c *Correlator) matchSystemOneLocked(ev *model.TraceEvent) (*sessionTrack, string, string) {
	goal := strings.TrimSpace(ev.SystemOne.Goal)
	var best *sessionTrack
	cutoff := ev.Timestamp - c.activeWindow.Milliseconds()
	for _, st := range c.sessions {
		if st.lastUpdatedAt < cutoff {
			continue
		}
		if strings.TrimSpace(st.goal) == goal {
			if best == nil || st.lastUpdatedAt > best.lastUpdatedAt {
				best = st
			}
		}
	}
	if best != nil {
		parent := best.lastStepEventID
		if parent == "" {
			parent = best.lastEventID
		}
		return best, parent, fmt.Sprintf("systemone_goal_match(recent_actions=%d)", ev.SystemOne.RecentActionCount)
	}
	return nil, "", ""
}

func (c *Correlator) matchChatPrefixLocked(ev *model.TraceEvent) (*sessionTrack, string, int, string) {
	reqHashes := hashMessages(ev.Chat.Messages)
	if len(reqHashes) <= 1 {
		return nil, "", 0, ""
	}
	cutoff := ev.Timestamp - c.activeWindow.Milliseconds()
	var bestSess *sessionTrack
	bestParent := ""
	bestPrefixLen := 0
	var bestSlidingSess *sessionTrack
	bestSlidingParent := ""
	bestSlidingPrefix := 0

	for _, st := range c.sessions {
		if st.lastUpdatedAt < cutoff {
			continue
		}
		for i := len(st.msgSnapshots) - 1; i >= 0; i-- {
			snap := st.msgSnapshots[i]
			if len(snap.fullHashes) > 0 && hasPrefixHashes(reqHashes, snap.fullHashes) && len(snap.fullHashes) > bestPrefixLen {
				bestSess = st
				bestParent = snap.eventID
				bestPrefixLen = len(snap.fullHashes)
			} else if len(snap.reqHashes) > 0 && len(reqHashes) > len(snap.reqHashes) && hasPrefixHashes(reqHashes, snap.reqHashes) && len(snap.reqHashes) > bestPrefixLen {
				bestSess = st
				bestParent = snap.eventID
				bestPrefixLen = len(snap.reqHashes)
			} else {
				if prefix, eventID, ok := matchSlidingSnapshot(reqHashes, snap); ok && prefix > bestSlidingPrefix {
					bestSlidingSess = st
					bestSlidingParent = eventID
					bestSlidingPrefix = prefix
				}
			}
		}
	}
	if bestSess != nil {
		return bestSess, bestParent, bestPrefixLen, fmt.Sprintf("messages_prefix_hash(matched=%d/%d)", bestPrefixLen, len(reqHashes))
	}
	if bestSlidingSess != nil {
		return bestSlidingSess, bestSlidingParent, bestSlidingPrefix,
			fmt.Sprintf("messages_sliding_window(matched=%d/%d)", bestSlidingPrefix, len(reqHashes))
	}
	return nil, "", 0, ""
}

func (c *Correlator) matchProcessTreeLocked(ev *model.TraceEvent) (*sessionTrack, string, string) {
	cutoff := ev.Timestamp - (5 * time.Minute).Milliseconds()
	var best *sessionTrack
	bestScore := 0
	bestReason := ""
	for _, st := range c.sessions {
		if st.lastUpdatedAt < cutoff {
			continue
		}
		score, reason := 0, ""
		switch {
		case ev.ConnKey != "" && st.connKeys[ev.ConnKey] && (ev.Process.PID == 0 || sameProcessTree(ev, st)):
			score, reason = 4, fmt.Sprintf("same_conn(%s)", ev.ConnKey)
		case ev.Process.PID > 0 && ev.Process.TID > 0 && st.pids[ev.Process.PID] && st.tids[ev.Process.TID]:
			score, reason = 3, fmt.Sprintf("same_tid(pid=%d,tid=%d)", ev.Process.PID, ev.Process.TID)
		case ev.Process.PID > 0 && st.pids[ev.Process.PID]:
			score, reason = 2, fmt.Sprintf("same_pid(%d)", ev.Process.PID)
		case ev.Process.PPID > 0 && (st.pids[ev.Process.PPID] || st.rootPID == ev.Process.PPID):
			score, reason = 1, fmt.Sprintf("child_of_pid(%d->%d)", ev.Process.PPID, ev.Process.PID)
		case ev.Process.Cwd != "" && st.cwd == ev.Process.Cwd && st.stepCount > 0:
			score, reason = 1, fmt.Sprintf("same_cwd(%s)", ev.Process.Cwd)
		}
		if score > bestScore || (score > 0 && score == bestScore && st.lastUpdatedAt > best.lastUpdatedAt) {
			best = st
			bestScore = score
			bestReason = reason
		}
	}
	if best != nil {
		parent := best.lastStepEventID
		if parent == "" {
			parent = best.lastEventID
		}
		return best, parent, bestReason
	}
	return nil, "", ""
}

func sameProcessTree(ev *model.TraceEvent, st *sessionTrack) bool {
	if ev.Process.PID > 0 && (st.pids[ev.Process.PID] || st.rootPID == ev.Process.PID) {
		return true
	}
	if ev.Process.PPID > 0 && (st.pids[ev.Process.PPID] || st.rootPID == ev.Process.PPID) {
		return true
	}
	return false
}

func (c *Correlator) recordSessionMembershipLocked(st *sessionTrack, ev *model.TraceEvent) {
	if ev.Process.PID > 0 {
		if st.pids == nil {
			st.pids = make(map[int]bool)
		}
		st.pids[ev.Process.PID] = true
	}
	if ev.Process.TID > 0 {
		if st.tids == nil {
			st.tids = make(map[int]bool)
		}
		st.tids[ev.Process.TID] = true
	}
	if ev.ConnKey != "" {
		if st.connKeys == nil {
			st.connKeys = make(map[string]bool)
		}
		st.connKeys[ev.ConnKey] = true
	}
}

func matchSlidingSnapshot(reqHashes []string, snap msgSnapshot) (int, string, bool) {
	for _, hist := range [][]string{snap.fullHashes, snap.reqHashes} {
		if len(hist) == 0 || len(reqHashes) <= 1 {
			continue
		}
		maxK := len(hist) - snap.leadingSystem
		if maxK >= len(reqHashes) {
			maxK = len(reqHashes) - 1
		}
		minK := 2
		if snap.nonSystemMessages == 1 && snap.lastMessageLength >= 64 {
			minK = 1
		}
		for k := maxK; k >= minK; k-- {
			tail := hist[len(hist)-k:]
			for start := 0; start+k < len(reqHashes); start++ {
				end := start + k
				if hasPrefixHashes(reqHashes[start:end], tail) {
					return end, snap.eventID, true
				}
			}
		}
	}
	return 0, "", false
}

func (c *Correlator) recordChatSnapshotLocked(st *sessionTrack, ev *model.TraceEvent) {
	if ev.Chat == nil || len(ev.Chat.Messages) == 0 {
		return
	}
	reqHashes := hashMessages(ev.Chat.Messages)
	fullHashes := append([]string(nil), reqHashes...)
	if ev.Chat.ResponseText != "" || len(ev.Chat.ToolCalls) > 0 {
		assistantMsg := model.ChatMessage{
			Role:      "assistant",
			Content:   ev.Chat.ResponseText,
			ToolCalls: ev.Chat.ToolCalls,
		}
		fullHashes = append(fullHashes, hashSingleMessage(assistantMsg))
	}
	st.msgSnapshots = append(st.msgSnapshots, msgSnapshot{
		eventID:           ev.ID,
		turnIndex:         ev.TurnIndex,
		reqHashes:         reqHashes,
		fullHashes:        fullHashes,
		leadingSystem:     leadingSystemMessageCount(ev.Chat.Messages),
		nonSystemMessages: len(ev.Chat.Messages) - leadingSystemMessageCount(ev.Chat.Messages),
		lastMessageLength: len([]rune(strings.TrimSpace(ev.Chat.Messages[len(ev.Chat.Messages)-1].Content))),
	})
	if len(st.msgSnapshots) > 64 {
		st.msgSnapshots = st.msgSnapshots[len(st.msgSnapshots)-64:]
	}
}

func leadingSystemMessageCount(msgs []model.ChatMessage) int {
	count := 0
	for _, msg := range msgs {
		if strings.EqualFold(strings.TrimSpace(msg.Role), "system") {
			count++
			continue
		}
		break
	}
	return count
}

func hashMessages(msgs []model.ChatMessage) []string {
	out := make([]string, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, hashSingleMessage(m))
	}
	return out
}

func hashSingleMessage(m model.ChatMessage) string {
	var b strings.Builder
	role := strings.ToLower(strings.TrimSpace(m.Role))
	if role == "model" {
		role = "assistant"
	}
	b.WriteString(role)
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(m.Content))
	if m.ToolCallID != "" {
		b.WriteByte('|')
		b.WriteString(strings.TrimSpace(m.ToolCallID))
	}
	for _, tc := range m.ToolCalls {
		b.WriteByte('|')
		b.WriteString(tc.Name)
		b.WriteByte(':')
		b.WriteString(strings.TrimSpace(tc.Arguments))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

func hasPrefixHashes(full, prefix []string) bool {
	if len(prefix) == 0 || len(full) < len(prefix) {
		return false
	}
	for i := range prefix {
		if full[i] != prefix[i] {
			return false
		}
	}
	return true
}

func extractExplicitSessionKeys(ev *model.TraceEvent) ([]string, string) {
	var keys []string
	var prevRespID string

	for k, v := range ev.RequestHeaders {
		lk := strings.ToLower(k)
		switch lk {
		case "x-session-id", "x-conversation-id", "x-thread-id", "openai-conversation-id",
			"mcp-session-id", "x-claude-session-id", "x-codex-session-id", "x-agent-session-id", "x-langsmith-trace-id":
			if strings.TrimSpace(v) != "" {
				keys = append(keys, lk+":"+strings.TrimSpace(v))
			}
		}
	}

	if ev.RequestRaw != "" {
		var req map[string]any
		if json.Unmarshal([]byte(ev.RequestRaw), &req) == nil {
			for _, field := range []string{"session_id", "conversation_id", "thread_id", "prompt_cache_key", "conversation"} {
				if val, ok := req[field].(string); ok && strings.TrimSpace(val) != "" {
					keys = append(keys, field+":"+strings.TrimSpace(val))
				}
			}
			if pr, ok := req["previous_response_id"].(string); ok && strings.TrimSpace(pr) != "" {
				prevRespID = strings.TrimSpace(pr)
			}
			if meta, ok := req["metadata"].(map[string]any); ok {
				for _, mf := range []string{"session_id", "conversation_id", "user_id", "trace_id"} {
					if val, ok := meta[mf].(string); ok && strings.TrimSpace(val) != "" {
						keys = append(keys, "meta."+mf+":"+strings.TrimSpace(val))
					}
				}
			}
		}
	}
	return keys, prevRespID
}

func extractResponseObjectID(respRaw string) string {
	if respRaw == "" {
		return ""
	}
	var obj map[string]any
	if json.Unmarshal([]byte(respRaw), &obj) == nil {
		if id, ok := obj["id"].(string); ok && strings.HasPrefix(id, "resp_") {
			return id
		}
	}
	for _, line := range strings.Split(respRaw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		var ev map[string]any
		if json.Unmarshal([]byte(payload), &ev) != nil {
			continue
		}
		if rObj, ok := ev["response"].(map[string]any); ok {
			if id, ok := rObj["id"].(string); ok && strings.HasPrefix(id, "resp_") {
				return id
			}
		}
		if id, ok := ev["id"].(string); ok && strings.HasPrefix(id, "resp_") {
			return id
		}
	}
	return ""
}

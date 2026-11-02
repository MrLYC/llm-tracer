package collector

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"testing"
	"time"

	"github.com/mrlyc/llm-tracer/internal/correlator"
	"github.com/mrlyc/llm-tracer/internal/model"
	"github.com/mrlyc/llm-tracer/internal/selfmon"
	"github.com/mrlyc/llm-tracer/internal/store"
	"github.com/stretchr/testify/require"
)

func newDirectExchangeSampleInput() DirectExchangeInput {
	return DirectExchangeInput{
		PID:         os.Getpid(),
		Comm:        "python3",
		Cmdline:     "python3 agent.py",
		Method:      "POST",
		Host:        "api.openai.com",
		Path:        "/v1/chat/completions",
		HTTPVersion: "HTTP/1.1",
		HTTPStatus:  200,
		DurationMs:  42,
		RequestHeaders: map[string]string{
			"Authorization": "Bearer sk-live-collector-secret-key",
			"X-VirtX-TOTP":  "JBSWY3DPEHPK3PXP",
			"Content-Type":  "application/json",
		},
		ResponseHeaders: map[string]string{
			"Set-Cookie":   "session=collector-resp-secret",
			"Content-Type": "application/json",
			"X-Request-Id": "req_collector_001",
		},
		RequestBody:  []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"collector gate test"}]}`),
		ResponseBody: []byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"total_tokens":10}}`),
	}
}

func TestCollectorLayerHeaderGating_IngestDirectExchange(t *testing.T) {
	dir := t.TempDir()
	mon, err := selfmon.NewMonitor(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mon.Close() })
	st, err := store.NewStore(dir, 10*time.Minute, mon)
	require.NoError(t, err)
	defer st.Close()
	corr := correlator.NewCorrelator(mon)

	// 1. Negative case (default RecordHeaders=false): returned *model.TraceEvent must have nil headers and HeadersRecorded=false
	colOff, err := NewCollector(dir, model.ScopeFilter{RecordHeaders: false}, corr, st, mon)
	require.NoError(t, err)

	evOff, matched, err := colOff.IngestDirectExchange(newDirectExchangeSampleInput())
	require.NoError(t, err)
	require.True(t, matched)
	require.NotNil(t, evOff)
	require.False(t, evOff.HeadersRecorded, "returned TraceEvent must have HeadersRecorded=false when scope.RecordHeaders=false")
	require.Nil(t, evOff.RequestHeaders, "returned TraceEvent RequestHeaders must be nil when scope.RecordHeaders=false")
	require.Nil(t, evOff.ResponseHeaders, "returned TraceEvent ResponseHeaders must be nil when scope.RecordHeaders=false")

	// 2. Positive case (RecordHeaders=true): returned *model.TraceEvent must preserve RequestHeaders and ResponseHeaders
	colOn, err := NewCollector(dir, model.ScopeFilter{RecordHeaders: true}, corr, st, mon)
	require.NoError(t, err)

	evOn, matched, err := colOn.IngestDirectExchange(newDirectExchangeSampleInput())
	require.NoError(t, err)
	require.True(t, matched)
	require.NotNil(t, evOn)
	require.True(t, evOn.HeadersRecorded, "returned TraceEvent must have HeadersRecorded=true when scope.RecordHeaders=true")
	require.NotNil(t, evOn.RequestHeaders, "returned TraceEvent RequestHeaders must be populated when scope.RecordHeaders=true")
	require.NotNil(t, evOn.ResponseHeaders, "returned TraceEvent ResponseHeaders must be populated when scope.RecordHeaders=true")
	require.Equal(t, "Bearer sk-live-collector-secret-key", evOn.RequestHeaders["Authorization"])
	require.Equal(t, "JBSWY3DPEHPK3PXP", evOn.RequestHeaders["X-VirtX-TOTP"])
	require.Equal(t, "session=collector-resp-secret", evOn.ResponseHeaders["Set-Cookie"])
	require.Equal(t, "req_collector_001", evOn.ResponseHeaders["X-Request-Id"])

	// 3. Dynamic UpdateScope toggle from true -> false must immediately gate headers off on returned *model.TraceEvent
	colOn.UpdateScope(model.ScopeFilter{RecordHeaders: false})
	evToggledOff, matched, err := colOn.IngestDirectExchange(newDirectExchangeSampleInput())
	require.NoError(t, err)
	require.True(t, matched)
	require.NotNil(t, evToggledOff)
	require.False(t, evToggledOff.HeadersRecorded)
	require.Nil(t, evToggledOff.RequestHeaders)
	require.Nil(t, evToggledOff.ResponseHeaders)
}

// TestCollectorLayerHeaderGating_ConstructorGateIsolation verifies that IngestDirectExchange
// in collector.go independently gates reqHdr/respHdr and HeadersRecorded behind scope.RecordHeaders
// before calling parser.ParseExchange or store.SaveEvent, so a single-layer mutation in collector.go
// cannot be masked by downstream layers.
func TestCollectorLayerHeaderGating_ConstructorGateIsolation(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "collector.go", nil, 0)
	require.NoError(t, err)

	var ingestFn *ast.FuncDecl
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "IngestDirectExchange" {
			ingestFn = fn
			break
		}
	}
	require.NotNil(t, ingestFn, "IngestDirectExchange must exist in collector.go")

	isScopeRecordHeaders := func(expr ast.Expr) bool {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "RecordHeaders" {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "scope"
	}

	isInHeaderAssign := func(stmt ast.Stmt, lhsName, rhsField string) bool {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return false
		}
		lhs, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || lhs.Name != lhsName {
			return false
		}
		sel, ok := assign.Rhs[0].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != rhsField {
			return false
		}
		xId, ok := sel.X.(*ast.Ident)
		return ok && xId.Name == "in"
	}

	gatedReqHdr := false
	gatedRespHdr := false
	ungatedHeaderAssign := false
	headersRecordedUsesScopeField := false

	for _, stmt := range ingestFn.Body.List {
		if isInHeaderAssign(stmt, "reqHdr", "RequestHeaders") || isInHeaderAssign(stmt, "respHdr", "ResponseHeaders") {
			ungatedHeaderAssign = true
		}
		if ifStmt, ok := stmt.(*ast.IfStmt); ok {
			if isScopeRecordHeaders(ifStmt.Cond) && ifStmt.Else == nil {
				for _, inner := range ifStmt.Body.List {
					if isInHeaderAssign(inner, "reqHdr", "RequestHeaders") {
						gatedReqHdr = true
					}
					if isInHeaderAssign(inner, "respHdr", "ResponseHeaders") {
						gatedRespHdr = true
					}
				}
			}
		}
		ast.Inspect(stmt, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if kId, ok := kv.Key.(*ast.Ident); ok && kId.Name == "HeadersRecorded" {
					if isScopeRecordHeaders(kv.Value) {
						headersRecordedUsesScopeField = true
					}
				}
			}
			return true
		})
	}

	require.False(t, ungatedHeaderAssign, "collector.go must not assign reqHdr/respHdr outside of `if scope.RecordHeaders` gate")
	require.True(t, gatedReqHdr, "collector.go must gate `reqHdr = in.RequestHeaders` behind `if scope.RecordHeaders`")
	require.True(t, gatedRespHdr, "collector.go must gate `respHdr = in.ResponseHeaders` behind `if scope.RecordHeaders`")
	require.True(t, headersRecordedUsesScopeField, "collector.go TraceEvent literal must set `HeadersRecorded: scope.RecordHeaders`")
}

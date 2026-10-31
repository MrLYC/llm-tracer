package selfmon

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelfmonRecordAndQuery(t *testing.T) {
	dir := t.TempDir()
	m, err := NewMonitor(dir)
	require.NoError(t, err)

	m.RecordOK(StageProbe, "attach_uprobe", map[string]any{"lib": "libssl.so.3"})
	m.RecordWarn(StageStream, "half_open_stream", "missing request", nil)
	m.RecordError(StageParser, "parse_json", errors.New("unexpected EOF"), map[string]any{"pid": 99})

	st := m.Stats()
	require.Equal(t, int64(1), st.TotalOK)
	require.Equal(t, int64(1), st.TotalWarn)
	require.Equal(t, int64(1), st.TotalError)
	require.NotNil(t, st.LastError)
	require.Equal(t, "unexpected EOF", st.LastError.Error)

	errEvs, err := m.QueryEvents(Query{Status: StatusError})
	require.NoError(t, err)
	require.Len(t, errEvs, 1)
	require.Equal(t, StageParser, errEvs[0].Stage)
}

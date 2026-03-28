package mcp

import (
	"encoding/json"
	"testing"
)

func FuzzMCPRequestParsing(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"skeptic_daemon_health"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var req MCPRequest
		if err := json.Unmarshal(data, &req); err != nil {
			return
		}
		if req.Params != nil {
			var params MCPToolsCallParams
			_ = json.Unmarshal(req.Params, &params)
		}
	})
}

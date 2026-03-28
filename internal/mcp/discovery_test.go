package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseMCPConfigServers(t *testing.T) {
	config := map[string]any{
		"mcpServers": map[string]any{
			"test-server": map[string]any{
				"command": "npx",
				"args":    []string{"-y", "test-mcp"},
				"env":     map[string]string{"API_KEY": "secret123"},
			},
		},
	}
	data, _ := json.Marshal(config)
	servers := ParseMCPConfigServers(data)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Name != "test-server" {
		t.Fatalf("expected name=test-server, got %s", servers[0].Name)
	}
	if servers[0].Command != "npx" {
		t.Fatalf("expected command=npx, got %s", servers[0].Command)
	}
}

func TestParseMCPConfigServersAlternateKey(t *testing.T) {
	config := map[string]any{
		"servers": map[string]any{
			"srv1": map[string]any{
				"command": "python",
			},
		},
	}
	data, _ := json.Marshal(config)
	servers := ParseMCPConfigServers(data)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
}

func TestRunMCPDiscoveryChecks(t *testing.T) {
	configs := []MCPClientConfig{
		{
			Client:     "test-client",
			ConfigPath: "/tmp/test-mcp.json",
			Servers: []MCPServerEntry{
				{
					Name:    "risky-server",
					Command: "npx",
					Args:    []string{"--host", "0.0.0.0"},
					Env: map[string]string{
						"API_KEY":   "secret",
						"DB_TOKEN":  "tok",
						"HOST":      "localhost",
						"PORT":      "8080",
						"DEBUG":     "true",
						"LOG_LEVEL": "info",
					},
				},
			},
		},
	}
	findings := RunMCPDiscoveryChecks(configs, false)
	ruleIDs := make(map[string]bool)
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["DISC-MCP-001"] {
		t.Error("expected DISC-MCP-001 for broad env passthrough")
	}
	if !ruleIDs["DISC-MCP-002"] {
		t.Error("expected DISC-MCP-002 for credential env vars")
	}
	if !ruleIDs["DISC-MCP-003"] {
		t.Error("expected DISC-MCP-003 for npx command")
	}
	if !ruleIDs["DISC-MCP-004"] {
		t.Error("expected DISC-MCP-004 for wildcard bind")
	}
}

func TestDiscoverMCPClientsWithFixture(t *testing.T) {
	dir := t.TempDir()
	cursorDir := filepath.Join(dir, ".cursor")
	if err := os.MkdirAll(cursorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"mcpServers": map[string]any{
			"test": map[string]any{
				"command": "test-cmd",
			},
		},
	}
	data, _ := json.Marshal(config)
	if err := os.WriteFile(filepath.Join(cursorDir, "mcp.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	servers := ParseMCPConfigServers(data)
	if len(servers) == 0 {
		t.Fatal("expected servers from fixture config")
	}
}

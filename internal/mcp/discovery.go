package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// MCPClientConfig represents a discovered MCP client installation with its server entries.
type MCPClientConfig struct {
	Client     string
	ConfigPath string
	Servers    []MCPServerEntry
}

// MCPServerEntry represents a single MCP server definition in a client config.
type MCPServerEntry struct {
	Name    string
	Command string
	Args    []string
	Env     map[string]string
}

// MCPCandidate describes a known MCP config file location for a client.
type MCPCandidate struct {
	Client string
	Path   string
}

// DiscoverMCPClients probes known filesystem paths for MCP client configs across platforms.
func DiscoverMCPClients() []MCPClientConfig {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}

	candidates := MCPClientCandidates(home)
	var configs []MCPClientConfig
	for _, c := range candidates {
		expanded := model.ExpandHomePath(c.Path)
		data, err := os.ReadFile(expanded)
		if err != nil {
			continue
		}
		servers := ParseMCPConfigServers(data)
		if len(servers) > 0 {
			configs = append(configs, MCPClientConfig{
				Client:     c.Client,
				ConfigPath: expanded,
				Servers:    servers,
			})
		}
	}
	return configs
}

// MCPClientCandidates returns default MCP config locations for the current OS plus editor-agnostic paths.
func MCPClientCandidates(home string) []MCPCandidate {
	candidates := []MCPCandidate{
		{"cursor-global", filepath.Join(home, ".cursor", "mcp.json")},
		{"cursor-project", filepath.Join(".", ".cursor", "mcp.json")},
		{"vscode", filepath.Join(home, ".vscode", "mcp.json")},
		{"windsurf", filepath.Join(home, ".windsurf", "mcp.json")},
		{"continue-dev", filepath.Join(home, ".continue", "config.json")},
	}
	switch runtime.GOOS {
	case "darwin":
		candidates = append(candidates,
			MCPCandidate{"claude-desktop", filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")},
			MCPCandidate{"claude-code", filepath.Join(home, "Library", "Application Support", "Claude Code", "config.json")},
			MCPCandidate{"github-copilot", filepath.Join(home, ".config", "github-copilot", "mcp.json")},
			MCPCandidate{"zed", filepath.Join(home, ".config", "zed", "settings.json")},
			MCPCandidate{"jetbrains", filepath.Join(home, "Library", "Application Support", "JetBrains", "mcp.json")},
		)
	case "linux":
		candidates = append(candidates,
			MCPCandidate{"claude-desktop", filepath.Join(home, ".config", "claude", "claude_desktop_config.json")},
			MCPCandidate{"claude-code", filepath.Join(home, ".config", "claude-code", "config.json")},
			MCPCandidate{"github-copilot", filepath.Join(home, ".config", "github-copilot", "mcp.json")},
			MCPCandidate{"zed", filepath.Join(home, ".config", "zed", "settings.json")},
			MCPCandidate{"jetbrains", filepath.Join(home, ".config", "JetBrains", "mcp.json")},
		)
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		candidates = append(candidates,
			MCPCandidate{"claude-desktop", filepath.Join(appData, "Claude", "claude_desktop_config.json")},
			MCPCandidate{"github-copilot", filepath.Join(home, ".config", "github-copilot", "mcp.json")},
			MCPCandidate{"zed", filepath.Join(appData, "Zed", "settings.json")},
			MCPCandidate{"jetbrains", filepath.Join(appData, "JetBrains", "mcp.json")},
		)
	}
	return candidates
}

// ParseMCPConfigServers extracts server entries from common MCP config JSON structures.
func ParseMCPConfigServers(data []byte) []MCPServerEntry {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	serversRaw, ok := raw["mcpServers"]
	if !ok {
		serversRaw, ok = raw["servers"]
	}
	if !ok {
		return nil
	}

	var serverMap map[string]json.RawMessage
	if err := json.Unmarshal(serversRaw, &serverMap); err != nil {
		return nil
	}

	entries := make([]MCPServerEntry, 0, len(serverMap))
	for name, val := range serverMap {
		var s struct {
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		}
		if err := json.Unmarshal(val, &s); err != nil {
			continue
		}
		entries = append(entries, MCPServerEntry{
			Name:    name,
			Command: s.Command,
			Args:    s.Args,
			Env:     s.Env,
		})
	}
	return entries
}

// RunMCPDiscoveryChecks scans discovered MCP configs for risky patterns.
func RunMCPDiscoveryChecks(configs []MCPClientConfig, redactSecrets bool) []model.Finding {
	var findings []model.Finding
	for _, cfg := range configs {
		for _, srv := range cfg.Servers {
			findings = append(findings, CheckMCPServerEntry(cfg.Client, cfg.ConfigPath, srv, redactSecrets)...)
		}
	}
	return findings
}

// CheckMCPServerEntry flags risky MCP server definitions: large env passthrough, credential-like env keys,
// runtime package runners, and wildcard network binds.
func CheckMCPServerEntry(client string, configPath string, srv MCPServerEntry, redactSecrets bool) []model.Finding {
	var findings []model.Finding
	fileLabel := configPath

	if len(srv.Env) > 5 {
		findings = append(findings, model.Finding{
			RuleID:      "DISC-MCP-001",
			Title:       "MCP server with broad environment passthrough",
			Description: fmt.Sprintf("MCP server %q in %s passes %d env vars, increasing exposure surface.", srv.Name, client, len(srv.Env)),
			Category:    "mcp-discovery",
			Mitre:       "T1059",
			Severity:    model.SeverityMedium,
			File:        fileLabel,
			Match:       security.SanitizeMatch(fmt.Sprintf("server=%s env_count=%d", srv.Name, len(srv.Env)), redactSecrets),
		})
	}

	for key, val := range srv.Env {
		upperKey := strings.ToUpper(key)
		if strings.Contains(upperKey, "TOKEN") || strings.Contains(upperKey, "SECRET") || strings.Contains(upperKey, "API_KEY") || strings.Contains(upperKey, "PASSWORD") {
			findings = append(findings, model.Finding{
				RuleID:      "DISC-MCP-002",
				Title:       "MCP server env contains credential-like variable",
				Description: fmt.Sprintf("MCP server %q in %s exposes env var %q.", srv.Name, client, key),
				Category:    "mcp-discovery",
				Mitre:       "T1552.001",
				Severity:    model.SeverityCritical,
				File:        fileLabel,
				Match:       security.SanitizeMatch(fmt.Sprintf("server=%s key=%s", srv.Name, key), redactSecrets),
			})
		}
		_ = val
	}

	if srv.Command != "" {
		lower := strings.ToLower(srv.Command)
		if strings.Contains(lower, "npx") || strings.Contains(lower, "uvx") {
			findings = append(findings, model.Finding{
				RuleID:      "DISC-MCP-003",
				Title:       "MCP server uses package-runner command",
				Description: fmt.Sprintf("MCP server %q in %s invokes %q, which downloads and executes packages at runtime.", srv.Name, client, srv.Command),
				Category:    "mcp-discovery",
				Mitre:       "T1204.002",
				Severity:    model.SeverityMedium,
				File:        fileLabel,
				Match:       security.SanitizeMatch(fmt.Sprintf("server=%s cmd=%s", srv.Name, srv.Command), redactSecrets),
			})
		}
	}

	for _, arg := range srv.Args {
		if strings.Contains(arg, "0.0.0.0") || strings.Contains(arg, "[::]") {
			findings = append(findings, model.Finding{
				RuleID:      "DISC-MCP-004",
				Title:       "MCP server binds to all interfaces",
				Description: fmt.Sprintf("MCP server %q in %s has a wildcard bind argument.", srv.Name, client),
				Category:    "mcp-discovery",
				Mitre:       "T1071",
				Severity:    model.SeverityHigh,
				File:        fileLabel,
				Match:       security.SanitizeMatch(fmt.Sprintf("server=%s arg=%s", srv.Name, arg), redactSecrets),
			})
		}
	}

	return findings
}

package scan

import "strings"

// ToolExemptions maps tool context names to rule ID prefixes that should be
// excluded when scanning content produced by that tool. This reduces false
// positives in agentic workflows where certain rule categories are expected
// noise for a given tool's output.
var ToolExemptions = map[string][]string{
	"bash":     {"EXEC-", "CMD-"},
	"shell":    {"EXEC-", "CMD-"},
	"edit":     {"EXTDL-"},
	"webfetch": {"SSRF-"},
	"curl":     {"SSRF-", "EXTDL-"},
	"wget":     {"SSRF-", "EXTDL-"},
}

// ExemptedRulePrefixes returns the rule ID prefixes to exclude for a tool name.
// Returns nil if the tool is unknown.
func ExemptedRulePrefixes(toolName string) []string {
	return ToolExemptions[strings.ToLower(strings.TrimSpace(toolName))]
}

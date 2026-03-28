package scan

import (
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// FindingMatchesThreatMode maps findings to a focus mode using both rule IDs and categories.
func FindingMatchesThreatMode(f model.Finding, mode model.ThreatMode) bool {
	if mode == model.ThreatModeAll {
		return true
	}
	ruleID := strings.ToUpper(strings.TrimSpace(f.RuleID))
	category := strings.ToLower(strings.TrimSpace(f.Category))

	switch mode {
	case model.ThreatModeMachineIdentity:
		if strings.HasPrefix(ruleID, "CLOUD-ID-") || strings.HasPrefix(ruleID, "MID-") || strings.HasPrefix(ruleID, "CI-SECRET-") {
			return true
		}
		if strings.HasPrefix(ruleID, "ATK-IMDS-") || strings.HasPrefix(ruleID, "ATK-SWEEP-") || strings.HasPrefix(ruleID, "ATK-MEMDUMP-") || ruleID == "ATK-COL-005" {
			return true
		}
		keywords := []string{"credential", "identity", "oauth", "auth", "machine-identity", "token"}
		for _, keyword := range keywords {
			if strings.Contains(category, keyword) {
				return true
			}
		}
		return false
	case model.ThreatModeAIWorkload:
		if strings.HasPrefix(ruleID, "AGT-") || strings.HasPrefix(ruleID, "AIW-") {
			return true
		}
		keywords := []string{"mcp", "skills", "memory", "agent", "ai", "tool-output"}
		for _, keyword := range keywords {
			if strings.Contains(category, keyword) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

// FilterFindingsByThreatMode applies domain focus filtering after full scan aggregation.
func FilterFindingsByThreatMode(findings []model.Finding, mode model.ThreatMode) []model.Finding {
	if mode == model.ThreatModeAll {
		return findings
	}
	filtered := make([]model.Finding, 0, len(findings))
	for _, finding := range findings {
		if FindingMatchesThreatMode(finding, mode) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

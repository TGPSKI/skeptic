package scan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// RollupFindings combines co-firing rules that identify the same normalized
// match at one location. The strongest finding remains primary and secondary
// IDs stay visible without inflating counts or risk scoring.
func RollupFindings(findings []model.Finding) []model.Finding {
	if len(findings) < 2 {
		return findings
	}
	out := make([]model.Finding, 0, len(findings))
	indexes := make(map[string]int, len(findings))
	for _, finding := range findings {
		key := rollupKey(finding)
		idx, exists := indexes[key]
		if !exists {
			finding.RelatedRuleIDs = uniqueRuleIDs(finding.RelatedRuleIDs, finding.RuleID)
			indexes[key] = len(out)
			out = append(out, finding)
			continue
		}
		primary := &out[idx]
		if strongerFinding(finding, *primary) {
			old := *primary
			*primary = finding
			primary.RelatedRuleIDs = mergeRelatedRuleIDs(finding, old)
		} else {
			primary.RelatedRuleIDs = mergeRelatedRuleIDs(*primary, finding)
		}
	}
	return out
}

func rollupKey(f model.Finding) string {
	normalized := strings.ToLower(strings.Join(strings.Fields(f.Match), " "))
	return fmt.Sprintf("%s\x00%d\x00%s", f.File, f.Line, normalized)
}

func strongerFinding(a, b model.Finding) bool {
	if rank := confidenceRank(a.ConfidenceClass) - confidenceRank(b.ConfidenceClass); rank != 0 {
		return rank > 0
	}
	if rank := model.SeverityWeight(a.Severity) - model.SeverityWeight(b.Severity); rank != 0 {
		return rank > 0
	}
	return a.RuleID < b.RuleID
}

func confidenceRank(class model.ConfidenceClass) int {
	switch class {
	case model.ConfidenceDefinitive:
		return 3
	case model.ConfidenceCorrelated:
		return 2
	default:
		return 1
	}
}

func mergeRelatedRuleIDs(primary, secondary model.Finding) []string {
	ids := append([]string{}, primary.RelatedRuleIDs...)
	ids = append(ids, secondary.RuleID)
	ids = append(ids, secondary.RelatedRuleIDs...)
	return uniqueRuleIDs(ids, primary.RuleID)
}

func uniqueRuleIDs(ids []string, primary string) []string {
	seen := map[string]struct{}{primary: {}}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

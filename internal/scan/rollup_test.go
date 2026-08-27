package scan

import (
	"slices"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestRollupFindingsKeepsStrongestPrimary(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "HEU-001", File: "a.yml", Line: 4, Match: " permissions: write-all ", Severity: model.SeverityCritical, ConfidenceClass: model.ConfidenceHeuristic},
		{RuleID: "SCM-001", File: "a.yml", Line: 4, Match: "permissions:   write-all", Severity: model.SeverityHigh, ConfidenceClass: model.ConfidenceDefinitive},
		{RuleID: "OTHER-001", File: "a.yml", Line: 5, Match: "permissions: write-all", Severity: model.SeverityHigh},
	}
	got := RollupFindings(findings)
	if len(got) != 2 {
		t.Fatalf("rollup count: got %d want 2", len(got))
	}
	if got[0].RuleID != "SCM-001" {
		t.Fatalf("primary rule: got %s", got[0].RuleID)
	}
	if !slices.Equal(got[0].RelatedRuleIDs, []string{"HEU-001"}) {
		t.Fatalf("related IDs: %#v", got[0].RelatedRuleIDs)
	}
}

func TestComputeRiskScoreSkipsSuppressedAndBenefitsFromRollup(t *testing.T) {
	raw := []model.Finding{
		{RuleID: "A", File: "a", Line: 1, Match: "same", Severity: model.SeverityHigh},
		{RuleID: "B", File: "a", Line: 1, Match: "same", Severity: model.SeverityHigh},
		{RuleID: "C", File: "c", Line: 1, Match: "other", Severity: model.SeverityCritical, Suppressed: true},
	}
	rolled := RollupFindings(raw)
	if got, want := ComputeRiskScore(rolled), 10; got != want {
		t.Fatalf("rolled risk score: got %d want %d", got, want)
	}
}

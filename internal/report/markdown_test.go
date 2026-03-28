package report

import (
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestWriteMarkdown_ZeroFindings(t *testing.T) {
	var buf strings.Builder
	r := model.Report{
		ScannedFiles: 10,
		SkippedFiles: 2,
		FindingsBySeverity: map[string]int{
			"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
		},
	}
	WriteMarkdown(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "## skeptic scan results") {
		t.Error("expected header")
	}
	if !strings.Contains(out, "| **Total** | **0** |") {
		t.Error("expected zero total")
	}
	if strings.Contains(out, "### Top findings") {
		t.Error("should not show top findings when empty")
	}
}

func TestWriteMarkdown_MixedSeverity(t *testing.T) {
	var buf strings.Builder
	r := model.Report{
		ScannedFiles: 100,
		SkippedFiles: 5,
		Findings: []model.Finding{
			{RuleID: "R1", Severity: model.SeverityCritical, File: "a.go", Line: 10, Title: "Crit hit"},
			{RuleID: "R2", Severity: model.SeverityHigh, File: "b.go", Title: "High hit"},
			{RuleID: "R3", Severity: model.SeverityMedium, File: "a.go", Line: 20, Title: "Med hit"},
		},
		FindingsBySeverity: map[string]int{
			"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0,
		},
		RiskScore: 42,
	}
	WriteMarkdown(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "| Critical | 1 |") {
		t.Error("expected critical count")
	}
	if !strings.Contains(out, "Risk score: 42") {
		t.Error("expected risk score")
	}
	if !strings.Contains(out, "### Top findings") {
		t.Error("expected top findings section")
	}
	if !strings.Contains(out, "`R1`") {
		t.Error("expected rule R1 in findings table")
	}
	if !strings.Contains(out, "### Files with most findings") {
		t.Error("expected file summary")
	}
}

func TestWriteMarkdown_ThresholdExceeded(t *testing.T) {
	var buf strings.Builder
	r := model.Report{
		ThresholdExceeded: true,
		FailOn:            model.SeverityHigh,
		FindingsBySeverity: map[string]int{
			"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0,
		},
		Findings: []model.Finding{
			{RuleID: "X1", Severity: model.SeverityHigh, File: "c.go", Title: "High"},
		},
	}
	WriteMarkdown(&buf, r)
	if !strings.Contains(buf.String(), "**Threshold exceeded**") {
		t.Error("expected threshold exceeded message")
	}
}

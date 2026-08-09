package report

import (
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestBuildSARIFRunIncludesBaselineState(t *testing.T) {
	report := model.Report{
		TargetPaths: []string{"/tmp"},
		Findings: []model.Finding{
			{
				RuleID:        "R-1",
				Title:         "rule one",
				Description:   "desc",
				Category:      "cat",
				Mitre:         "T1059",
				Severity:      model.SeverityHigh,
				File:          "a.txt",
				Line:          2,
				Match:         "hit",
				BaselineState: "new",
			},
		},
	}
	run := BuildSARIFRun(report)
	results, ok := run["results"].([]any)
	if !ok || len(results) != 1 {
		t.Fatalf("expected one SARIF result, got %#v", run["results"])
	}
	result := results[0].(map[string]any)
	if result["baselineState"] != "new" {
		t.Fatalf("expected baselineState=new, got %#v", result["baselineState"])
	}
}

func TestSarifLevelFromSeverity(t *testing.T) {
	cases := map[model.Severity]string{
		model.SeverityCritical: "error",
		model.SeverityHigh:     "error",
		model.SeverityMedium:   "warning",
		model.SeverityLow:      "note",
		model.SeverityInfo:     "note",
	}
	for sev, want := range cases {
		if got := SARIFLevelFromSeverity(sev); got != want {
			t.Fatalf("SARIFLevelFromSeverity(%s)=%s want=%s", sev, got, want)
		}
	}
}

func TestBuildSARIFRunDriverVersionAndInvocations(t *testing.T) {
	report := model.Report{
		GeneratedAt:     "2026-03-28T12:00:00Z",
		ScanCompletedAt: "2026-03-28T12:00:05Z",
		ToolVersion:     "commit@build",
		Findings:        []model.Finding{},
	}
	run := BuildSARIFRun(report)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "skeptic" {
		t.Fatalf("driver name: got %v", driver["name"])
	}
	if driver["version"] != "commit@build" {
		t.Fatalf("driver version: got %v", driver["version"])
	}
	inv := run["invocations"].([]any)[0].(map[string]any)
	if inv["startTimeUtc"] != report.GeneratedAt {
		t.Fatalf("startTimeUtc: got %v", inv["startTimeUtc"])
	}
	if inv["endTimeUtc"] != report.ScanCompletedAt {
		t.Fatalf("endTimeUtc: got %v", inv["endTimeUtc"])
	}
}

func TestBuildSARIFRunDefaultToolVersionUnknown(t *testing.T) {
	run := BuildSARIFRun(model.Report{
		GeneratedAt:     "2026-01-01T00:00:00Z",
		ScanCompletedAt: "2026-01-01T00:00:01Z",
		Findings:        []model.Finding{},
	})
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["version"] != "unknown" {
		t.Fatalf("expected unknown tool version, got %v", driver["version"])
	}
}

func TestBuildSARIFRunIncludesModeProperties(t *testing.T) {
	report := model.Report{
		TargetPaths:  []string{"/tmp"},
		Profile:      model.ProfileRepo,
		ScanStyle:    model.ScanStyleHybrid,
		ThreatMode:   model.ThreatModeAIWorkload,
		PolicyChecks: true,
		Findings:     []model.Finding{},
	}
	run := BuildSARIFRun(report)
	props, ok := run["properties"].(map[string]any)
	if !ok {
		t.Fatalf("missing properties map in SARIF run")
	}
	if props["scanStyle"] != model.ScanStyleHybrid {
		t.Fatalf("expected scanStyle property")
	}
	if props["threatMode"] != model.ThreatModeAIWorkload {
		t.Fatalf("expected threatMode property")
	}
	if props["policyChecks"] != true {
		t.Fatalf("expected policyChecks=true")
	}
}

// A waived finding stays in the report, so SARIF has to mark it suppressed.
// Without this, code scanning opens an alert for every waived finding and the
// check fails on a scan that exited 0 (#96).
func TestSARIFEmitsSuppressionsForWaivedFindings(t *testing.T) {
	report := model.Report{
		TargetPaths: []string{"."},
		Findings: []model.Finding{
			{
				RuleID:            "SCM-TRUST-001",
				Title:             "Mutable action ref",
				Severity:          model.SeverityHigh,
				File:              "docs/GITHUB_ACTION.md",
				Line:              8,
				Suppressed:        true,
				SuppressionReason: "Documented usage example.",
			},
			{
				RuleID:   "CI-PRT-001",
				Title:    "Privileged PR trigger",
				Severity: model.SeverityHigh,
				File:     ".github/workflows/x.yml",
				Line:     4,
			},
		},
	}

	run := BuildSARIFRun(report)
	results, ok := run["results"].([]any)
	if !ok || len(results) != 2 {
		t.Fatalf("expected 2 results, got %#v", run["results"])
	}

	byRule := map[string]map[string]any{}
	for _, r := range results {
		m := r.(map[string]any)
		byRule[m["ruleId"].(string)] = m
	}

	waived := byRule["SCM-TRUST-001"]
	sups, ok := waived["suppressions"].([]any)
	if !ok || len(sups) != 1 {
		t.Fatalf("waived finding: expected 1 suppression, got %#v", waived["suppressions"])
	}
	sup := sups[0].(map[string]any)
	if sup["kind"] != "external" {
		t.Errorf("kind = %v, want external", sup["kind"])
	}
	if sup["justification"] != "Documented usage example." {
		t.Errorf("justification = %v", sup["justification"])
	}

	if _, present := byRule["CI-PRT-001"]["suppressions"]; present {
		t.Error("unsuppressed finding must not carry a suppressions key")
	}
}

// A waiver with an empty reason still suppresses; the key is simply omitted.
func TestSARIFSuppressionWithoutReasonOmitsJustification(t *testing.T) {
	report := model.Report{
		Findings: []model.Finding{{
			RuleID:     "X-001",
			Severity:   model.SeverityLow,
			File:       "a.txt",
			Suppressed: true,
		}},
	}
	results := BuildSARIFRun(report)["results"].([]any)
	sup := results[0].(map[string]any)["suppressions"].([]any)[0].(map[string]any)
	if sup["kind"] != "external" {
		t.Errorf("kind = %v, want external", sup["kind"])
	}
	if _, present := sup["justification"]; present {
		t.Error("justification must be omitted when the reason is empty")
	}
}

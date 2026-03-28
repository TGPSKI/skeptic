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

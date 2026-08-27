package report

import (
	"path/filepath"
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

func TestBuildSARIFRunUsesRepositoryRelativeArtifacts(t *testing.T) {
	base := t.TempDir()
	scanRoot := filepath.Join(base, "testdata", "proof")
	report := model.Report{
		TargetPaths:        []string{scanRoot},
		SARIFBasePath:      base,
		ToolInformationURI: "https://github.com/example/skeptic",
		Findings:           []model.Finding{{RuleID: "R-1", Title: "rule", Severity: model.SeverityHigh, File: "nested/a.yml"}},
	}
	run := BuildSARIFRun(report)
	bases := run["originalUriBaseIds"].(map[string]any)
	if _, ok := bases["%SRCROOT%"]; !ok {
		t.Fatal("missing %SRCROOT% original URI base")
	}
	result := run["results"].([]any)[0].(map[string]any)
	location := result["locations"].([]any)[0].(map[string]any)
	physical := location["physicalLocation"].(map[string]any)
	artifact := physical["artifactLocation"].(map[string]any)
	if got, want := artifact["uri"], "testdata/proof/nested/a.yml"; got != want {
		t.Fatalf("artifact uri: got %v want %v", got, want)
	}
	if artifact["uriBaseId"] != "%SRCROOT%" {
		t.Fatalf("artifact uriBaseId: got %v", artifact["uriBaseId"])
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["informationUri"] != report.ToolInformationURI {
		t.Fatalf("informationUri: got %v", driver["informationUri"])
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

// A waived finding produces no SARIF result. GitHub code scanning turns every
// result into an alert and does not honor result.suppressions, so emitting a
// suppressed finding opens an alert for something already reviewed (#98).
func TestSARIFOmitsSuppressedFindings(t *testing.T) {
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
	if !ok {
		t.Fatalf("results missing: %#v", run["results"])
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for 2 findings (1 waived), got %d", len(results))
	}
	if got := results[0].(map[string]any)["ruleId"]; got != "CI-PRT-001" {
		t.Errorf("ruleId = %v, want CI-PRT-001", got)
	}

	// A suppressed finding must not contribute a rule descriptor either. A rule
	// with no result is harmless but advertises a detection that produced
	// nothing.
	rules := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]map[string]any)
	for _, r := range rules {
		if r["id"] == "SCM-TRUST-001" {
			t.Error("waived finding contributed a rule descriptor")
		}
	}
}

// Every finding waived means an empty result set, not a missing key: SARIF
// requires results to be present.
func TestSARIFAllSuppressedYieldsEmptyResults(t *testing.T) {
	report := model.Report{
		Findings: []model.Finding{
			{RuleID: "A-001", Severity: model.SeverityHigh, File: "a.txt", Suppressed: true},
			{RuleID: "B-001", Severity: model.SeverityLow, File: "b.txt", Suppressed: true},
		},
	}
	run := BuildSARIFRun(report)
	results, ok := run["results"].([]any)
	if !ok {
		t.Fatalf("results key must be present even when empty, got %#v", run["results"])
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

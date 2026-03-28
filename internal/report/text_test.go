package report

import (
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestWriteTextReportSingleTarget(t *testing.T) {
	var buf strings.Builder
	r := model.Report{
		TargetPath:         "/tmp/repo",
		Profile:            model.ProfileRepo,
		ScanStyle:          model.ScanStyleHybrid,
		ThreatMode:         model.ThreatModeAll,
		RulesetHash:        "abc123",
		ScannedFiles:       10,
		SkippedFiles:       2,
		FindingsBySeverity: map[string]int{"high": 1},
		Findings: []model.Finding{
			{RuleID: "R-1", Title: "test", Severity: model.SeverityHigh, File: "a.go", Line: 5, Category: "cat", Mitre: "T1059", Match: "hit"},
		},
	}
	WriteTextReport(&buf, r)
	out := buf.String()
	for _, want := range []string{"skeptic target: /tmp/repo", "profile: repo", "scan style: hybrid", "ruleset hash: abc123", "scanned files: 10", "[HIGH/HEURISTIC] R-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestWriteTextReportMultiTarget(t *testing.T) {
	var buf strings.Builder
	r := model.Report{
		TargetPaths:        []string{"/a", "/b"},
		Profile:            model.ProfileRepo,
		ScanStyle:          model.ScanStylePattern,
		ThreatMode:         model.ThreatModeAll,
		ScannedFiles:       5,
		FindingsBySeverity: map[string]int{},
	}
	WriteTextReport(&buf, r)
	out := buf.String()
	if !strings.Contains(out, "skeptic targets (2):") {
		t.Errorf("expected multi-target header, got:\n%s", out)
	}
	if !strings.Contains(out, "no findings") {
		t.Errorf("expected 'no findings'")
	}
}

func TestWriteTextReportAllBranches(t *testing.T) {
	var buf strings.Builder
	r := model.Report{
		TargetPath:         "/tmp",
		Profile:            model.ProfileRepo,
		ScanStyle:          model.ScanStyleHybrid,
		ThreatMode:         model.ThreatModeAll,
		Incremental:        true,
		StateCachePath:     "/tmp/cache",
		CacheSkippedFiles:  3,
		ScannedFiles:       10,
		SkippedFiles:       2,
		PermissionErrors:   1,
		MaxFilesReached:    true,
		MaxFiles:           100,
		MaxFindingsReached: true,
		MaxFindings:        50,
		DroppedFindings:    5,
		RedactedMatches:    true,
		BaselinePath:       "/tmp/baseline.json",
		NewFindings:        2,
		UnchangedFindings:  3,
		ResolvedFindings:   1,
		DiffOnly:           true,
		FailOn:             model.SeverityHigh,
		ThresholdExceeded:  true,
		FindingsBySeverity: map[string]int{"high": 1},
		Findings: []model.Finding{
			{RuleID: "R-1", Title: "test", Severity: model.SeverityHigh, File: "a.go", Category: "cat", Mitre: "T1059", Match: "hit", BaselineState: "new"},
		},
	}
	WriteTextReport(&buf, r)
	out := buf.String()
	for _, want := range []string{
		"incremental mode: enabled",
		"state cache: /tmp/cache",
		"cache-skipped files: 3",
		"permission errors skipped: 1",
		"scan limit reached: max-files=100",
		"finding limit reached: max-findings=50",
		"match redaction: enabled",
		"baseline: /tmp/baseline.json",
		"baseline diff:",
		"threshold exceeded",
		"[HIGH/NEW/HEURISTIC] R-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestWriteSARIFReportOutput(t *testing.T) {
	var buf strings.Builder
	r := model.Report{
		TargetPaths: []string{"/tmp"},
		Findings: []model.Finding{
			{RuleID: "R-1", Title: "test", Description: "desc", Severity: model.SeverityHigh, File: "a.go", Line: 1, Match: "hit", Category: "cat", Mitre: "T1059"},
		},
	}
	if err := WriteSARIFReport(&buf, r); err != nil {
		t.Fatalf("WriteSARIFReport error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{`"version": "2.1.0"`, `"ruleId": "R-1"`, `"level": "error"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in SARIF output", want)
		}
	}
}

func TestApplyBaselineDiffFiltersDiffOnly(t *testing.T) {
	report := &model.Report{
		Findings: []model.Finding{
			{RuleID: "R-1", File: "a.go", Line: 1, Severity: model.SeverityHigh, Match: "m1"},
			{RuleID: "R-2", File: "b.go", Line: 2, Severity: model.SeverityMedium, Match: "m2"},
		},
		FindingsBySeverity: map[string]int{},
	}
	baseline := model.Report{
		Findings: []model.Finding{
			{RuleID: "R-1", File: "a.go", Line: 1, Severity: model.SeverityHigh, Match: "m1"},
			{RuleID: "R-3", File: "c.go", Line: 3, Severity: model.SeverityLow, Match: "m3"},
		},
	}
	ApplyBaselineDiff(report, baseline, true)
	if report.NewFindings != 1 {
		t.Errorf("new findings = %d, want 1", report.NewFindings)
	}
	if report.UnchangedFindings != 1 {
		t.Errorf("unchanged = %d, want 1", report.UnchangedFindings)
	}
	if report.ResolvedFindings != 1 {
		t.Errorf("resolved = %d, want 1", report.ResolvedFindings)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("diff-only should filter to 1 finding, got %d", len(report.Findings))
	}
	if report.Findings[0].RuleID != "R-2" {
		t.Errorf("remaining finding should be R-2, got %s", report.Findings[0].RuleID)
	}
}

func TestApplyBaselineDiffNilReport(t *testing.T) {
	ApplyBaselineDiff(nil, model.Report{}, false)
}

func TestBuildEvidenceManifestAndSnippets(t *testing.T) {
	r := model.Report{
		ScannedFiles:       5,
		RulesetHash:        "abc",
		ScanStyle:          model.ScanStyleHybrid,
		ThreatMode:         model.ThreatModeAll,
		FindingsBySeverity: map[string]int{"high": 1},
		Findings: []model.Finding{
			{RuleID: "R-1", Severity: model.SeverityHigh, File: "a.go", Line: 3, Match: "hit"},
		},
	}
	reportJSON := []byte(`{}`)
	manifest := BuildEvidenceManifest(r, reportJSON)
	if manifest["total_findings"] != 1 {
		t.Errorf("total_findings = %v", manifest["total_findings"])
	}
	if manifest["scanned_files"] != 5 {
		t.Errorf("scanned_files = %v", manifest["scanned_files"])
	}

	snippets := BuildEvidenceSnippets(r)
	if len(snippets) != 1 {
		t.Fatalf("snippets len = %d, want 1", len(snippets))
	}
	if snippets[0]["rule_id"] != "R-1" {
		t.Errorf("snippet rule_id = %v", snippets[0]["rule_id"])
	}
}

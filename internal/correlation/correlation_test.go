package correlation

import (
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestRunCorrelationNoFindings(t *testing.T) {
	results := RunCorrelation(nil)
	if len(results) != 0 {
		t.Fatalf("expected no correlation findings from nil input")
	}
}

func TestRunCorrelationCOR001(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "SCM-TRUST-001", File: ".github/workflows/ci.yml", Severity: model.SeverityHigh},
		{RuleID: "BHV-CI-001", File: ".github/workflows/ci.yml", Severity: model.SeverityMedium},
	}
	results := RunCorrelation(findings)
	found := false
	for _, r := range results {
		if r.RuleID == "COR-001" {
			found = true
			if len(r.References) == 0 {
				t.Error("COR-001 should have references")
			}
			if want := 1.0; r.Confidence != want {
				t.Errorf("COR-001 confidence: got %v want %v", r.Confidence, want)
			}
		}
	}
	if !found {
		t.Fatal("expected COR-001 correlation finding")
	}
}

func TestRunCorrelationCOR003(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "AGT-MCP-001", File: "mcp/config.json", Severity: model.SeverityHigh},
		{RuleID: "ATK-COL-001", File: "mcp/handler.py", Severity: model.SeverityMedium},
	}
	results := RunCorrelation(findings)
	found := false
	for _, r := range results {
		if r.RuleID == "COR-003" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected COR-003 correlation finding")
	}
}

func TestRunRepoLevelCorrelationCOR004(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "AGT-SKL-001", File: "skills/x/SKILL.md", Severity: model.SeverityHigh, ConfidenceClass: model.ConfidenceHeuristic},
		{RuleID: "ATK-PER-001", File: "systemd/app.service", Severity: model.SeverityMedium, ConfidenceClass: model.ConfidenceDefinitive},
	}
	out := RunRepoLevelCorrelation(findings, RepoLevelCorrelationSpecs)
	var cor004 bool
	for _, f := range out {
		if f.RuleID == "COR-004" {
			cor004 = true
			if f.File != "(repo)" {
				t.Errorf("expected repo scope file label, got %q", f.File)
			}
		}
	}
	if !cor004 {
		t.Fatal("expected COR-004 repo-level correlation")
	}
}

func TestRunRepoLevelCorrelationCOR005(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "CLOUD-ID-001", File: "infra/role.yaml", Severity: model.SeverityHigh, ConfidenceClass: model.ConfidenceDefinitive},
		{RuleID: "AGT-MCP-001", File: ".cursor/mcp.json", Severity: model.SeverityMedium, ConfidenceClass: model.ConfidenceHeuristic},
	}
	out := RunRepoLevelCorrelation(findings, RepoLevelCorrelationSpecs)
	var cor005 bool
	for _, f := range out {
		if f.RuleID == "COR-005" {
			cor005 = true
			if f.File != "(repo)" {
				t.Errorf("expected repo scope file label, got %q", f.File)
			}
		}
	}
	if !cor005 {
		t.Fatal("expected COR-005 repo-level correlation")
	}
}

func TestRunRepoLevelCorrelationCOR006(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "CI-DEPBOT-001", File: "renovate.json", Severity: model.SeverityCritical, ConfidenceClass: model.ConfidenceDefinitive},
		{RuleID: "SCM-PKG-003", File: "package.json", Severity: model.SeverityMedium, ConfidenceClass: model.ConfidenceHeuristic},
	}
	out := RunRepoLevelCorrelation(findings, RepoLevelCorrelationSpecs)
	var cor006 bool
	for _, f := range out {
		if f.RuleID == "COR-006" {
			cor006 = true
			if f.File != "(repo)" {
				t.Errorf("expected repo scope file label, got %q", f.File)
			}
		}
	}
	if !cor006 {
		t.Fatal("expected COR-006: depbot no release age + install hooks should correlate (PR check execution vector)")
	}
}

func TestRunRepoLevelCorrelationPureHeuristicBlocked(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "AGT-SKL-001", File: "skills/x/SKILL.md", Severity: model.SeverityHigh, ConfidenceClass: model.ConfidenceHeuristic},
		{RuleID: "ATK-PER-001", File: "systemd/app.service", Severity: model.SeverityMedium, ConfidenceClass: model.ConfidenceHeuristic},
	}
	out := RunRepoLevelCorrelation(findings, RepoLevelCorrelationSpecs)
	for _, f := range out {
		if f.RuleID == "COR-004" {
			t.Fatal("COR-004 should not fire when all contributing findings share the same confidence class")
		}
	}
}

func TestRunCorrelationNoMatch(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "AGT-MCP-001", File: "foo/a.txt", Severity: model.SeverityLow},
	}
	results := RunCorrelation(findings)
	for _, r := range results {
		if r.RuleID == "COR-001" || r.RuleID == "COR-002" || r.RuleID == "COR-003" {
			t.Fatalf("unexpected correlation match: %s", r.RuleID)
		}
	}
}

func TestMatchesAllPatterns(t *testing.T) {
	ids := []string{"SCM-TRUST-001", "BHV-CI-002"}
	if !MatchesAllPatterns(ids, []string{"SCM-TRUST-001", "(BHV-CI-|CI-ABUSE-)"}) {
		t.Fatal("expected match")
	}
	if MatchesAllPatterns(ids, []string{"SCM-TRUST-001", "NONEXISTENT-"}) {
		t.Fatal("expected no match")
	}
}

func TestGroupFindingsByDir(t *testing.T) {
	findings := []model.Finding{
		{File: "a/file1.txt"},
		{File: "a/file2.txt"},
		{File: "b/file3.txt"},
	}
	groups := GroupFindingsByDir(findings)
	if len(groups["a"]) != 2 {
		t.Errorf("expected 2 findings in dir 'a', got %d", len(groups["a"]))
	}
	if len(groups["b"]) != 1 {
		t.Errorf("expected 1 finding in dir 'b', got %d", len(groups["b"]))
	}
	if _, ok := groups["(global)"]; ok {
		t.Error("did not expect (global) synthetic group")
	}
}

func TestCorrelateByFileBasenameCORFILE001(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "SCM-TRUST-001", File: "proj-a/.github/workflows/deploy.yml", ConfidenceClass: model.ConfidenceDefinitive},
		{RuleID: "BHV-CI-002", File: "proj-b/.github/workflows/deploy.yml", ConfidenceClass: model.ConfidenceHeuristic},
		{RuleID: "ENC-EXFIL-003", File: "proj-c/.github/workflows/deploy.yml", ConfidenceClass: model.ConfidenceDefinitive},
		{RuleID: "AGT-SKL-004", File: "proj-d/.github/workflows/deploy.yml", ConfidenceClass: model.ConfidenceHeuristic},
	}
	results := RunCorrelation(findings)
	found := false
	for _, r := range results {
		if r.RuleID == "COR-FILE-001" && r.File == "deploy.yml" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected COR-FILE-001 for shared workflow basename across rule families")
	}
}

func TestContentHashCorrelation(t *testing.T) {
	payload := "malicious-payload-xyz"
	findings := []model.Finding{
		{RuleID: "R1", File: "a/x.txt", Match: payload},
		{RuleID: "R2", File: "b/y.txt", Match: payload},
		{RuleID: "R3", File: "c/z.txt", Match: payload},
		{RuleID: "R4", File: "d/w.txt", Match: payload},
	}
	out := ContentHashFindings(findings)
	if len(out) != 1 || out[0].RuleID != "COR-PAYLOAD-001" {
		t.Fatalf("expected one COR-PAYLOAD-001, got %#v", out)
	}
}

func TestContentHashCorrelationTooFew(t *testing.T) {
	payload := "same-in-two-files"
	findings := []model.Finding{
		{RuleID: "R1", File: "a/x.txt", Match: payload},
		{RuleID: "R2", File: "b/y.txt", Match: payload},
	}
	out := ContentHashFindings(findings)
	for _, f := range out {
		if f.RuleID == "COR-PAYLOAD-001" {
			t.Fatalf("unexpected COR-PAYLOAD-001 with only 2 files")
		}
	}
}

func TestContentHashCorrelationThresholdPinned(t *testing.T) {
	payload := "threshold-test-payload"

	threeFiles := []model.Finding{
		{RuleID: "R1", File: "a/x.txt", Match: payload},
		{RuleID: "R2", File: "b/y.txt", Match: payload},
		{RuleID: "R3", File: "c/z.txt", Match: payload},
	}
	out := ContentHashFindings(threeFiles)
	for _, f := range out {
		if f.RuleID == "COR-PAYLOAD-001" {
			t.Fatal("COR-PAYLOAD-001 must not fire with exactly 3 files (threshold is 4)")
		}
	}

	fourFiles := []model.Finding{
		{RuleID: "R1", File: "a/x.txt", Match: payload},
		{RuleID: "R2", File: "b/y.txt", Match: payload},
		{RuleID: "R3", File: "c/z.txt", Match: payload},
		{RuleID: "R4", File: "d/w.txt", Match: payload},
	}
	out = ContentHashFindings(fourFiles)
	found := false
	for _, f := range out {
		if f.RuleID == "COR-PAYLOAD-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("COR-PAYLOAD-001 must fire with exactly 4 files (threshold is 4)")
	}
}

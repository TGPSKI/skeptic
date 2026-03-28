package suppress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func mockScanFn(findings []model.Finding) ScanFunc {
	return func(repoPath string) (*model.Report, error) {
		return &model.Report{Findings: findings}, nil
	}
}

func TestRunWaive_PerFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(fp, []byte("# Skill\nsome content"), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "waivers.json")

	findings := []model.Finding{
		{RuleID: "AGT-MCP-004", File: fp},
		{RuleID: "AGT-SKL-008", File: fp},
		{RuleID: "OTHER-001", File: filepath.Join(dir, "other.go")},
	}

	result, err := RunWaive(WaiveOptions{
		RepoPath:   dir,
		File:       fp,
		Reason:     "reviewed doc",
		WaiverPath: outPath,
	}, mockScanFn(findings))
	if err != nil {
		t.Fatalf("RunWaive: %v", err)
	}
	if result.MatchedFindings != 2 {
		t.Fatalf("expected 2 matched, got %d", result.MatchedFindings)
	}
	if result.WaiversCreated != 2 {
		t.Fatalf("expected 2 waivers, got %d", result.WaiversCreated)
	}
	if result.FileSHA256 == "" {
		t.Fatal("expected FileSHA256 to be populated")
	}

	wf, err := LoadWaiverFile(outPath)
	if err != nil {
		t.Fatalf("LoadWaiverFile: %v", err)
	}
	if len(wf.Waivers) != 2 {
		t.Fatalf("expected 2 waivers in file, got %d", len(wf.Waivers))
	}
	for _, w := range wf.Waivers {
		if w.FileSHA256 == "" {
			t.Fatalf("waiver %s missing SHA256", w.RuleID)
		}
	}
}

func TestRunWaive_PerFinding(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(fp, []byte("key: value"), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "waivers.json")

	findings := []model.Finding{
		{RuleID: "AGT-MCP-004", File: fp},
		{RuleID: "AGT-SKL-008", File: fp},
	}

	result, err := RunWaive(WaiveOptions{
		RepoPath:   dir,
		File:       fp,
		RuleID:     "AGT-MCP-004",
		Reason:     "specific rule",
		WaiverPath: outPath,
	}, mockScanFn(findings))
	if err != nil {
		t.Fatalf("RunWaive: %v", err)
	}
	if result.MatchedFindings != 1 {
		t.Fatalf("expected 1 matched, got %d", result.MatchedFindings)
	}
	if result.WaiversCreated != 1 {
		t.Fatalf("expected 1 waiver, got %d", result.WaiversCreated)
	}
}

func TestRunWaive_RuleOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "waivers.json")

	findings := []model.Finding{
		{RuleID: "SCM-TEMP-002", File: "/a/.env.example"},
		{RuleID: "SCM-TEMP-002", File: "/b/.env.example"},
		{RuleID: "OTHER-001", File: "/c/main.go"},
	}

	result, err := RunWaive(WaiveOptions{
		RepoPath:   dir,
		RuleID:     "SCM-TEMP-002",
		Reason:     "global rule waiver",
		WaiverPath: outPath,
	}, mockScanFn(findings))
	if err != nil {
		t.Fatalf("RunWaive: %v", err)
	}
	if result.MatchedFindings != 2 {
		t.Fatalf("expected 2 matched, got %d", result.MatchedFindings)
	}
}

func TestRunWaive_MergeExisting(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp := filepath.Join(dir, "target.md")
	if err := os.WriteFile(fp, []byte("doc"), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "waivers.json")

	existing := WaiverFile{
		Version: 1,
		Waivers: []Waiver{
			{RuleID: "EXISTING-001", Reason: "old waiver"},
		},
	}
	data, _ := json.MarshalIndent(existing, "", "  ")
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	findings := []model.Finding{
		{RuleID: "NEW-001", File: fp},
	}

	_, err := RunWaive(WaiveOptions{
		RepoPath:   dir,
		File:       fp,
		Reason:     "new waiver",
		WaiverPath: outPath,
	}, mockScanFn(findings))
	if err != nil {
		t.Fatalf("RunWaive: %v", err)
	}

	wf, err := LoadWaiverFile(outPath)
	if err != nil {
		t.Fatalf("LoadWaiverFile: %v", err)
	}
	if len(wf.Waivers) != 2 {
		t.Fatalf("expected 2 waivers (1 old + 1 new), got %d", len(wf.Waivers))
	}
}

func TestRunWaive_MissingReason(t *testing.T) {
	t.Parallel()
	_, err := RunWaive(WaiveOptions{
		RepoPath: "/tmp",
		File:     "x.go",
	}, mockScanFn(nil))
	if err == nil {
		t.Fatal("expected error for missing reason")
	}
}

func TestRunWaive_MissingFileAndRule(t *testing.T) {
	t.Parallel()
	_, err := RunWaive(WaiveOptions{
		RepoPath: "/tmp",
		Reason:   "test",
	}, mockScanFn(nil))
	if err == nil {
		t.Fatal("expected error when neither file nor rule specified")
	}
}

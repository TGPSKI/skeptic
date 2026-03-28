package scan

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestShouldSkipDirAndThresholdExceeded(t *testing.T) {
	if !ShouldSkipDir(model.ProfileRepo, ".git") {
		t.Fatalf("expected repo profile to skip .git")
	}
	if !ShouldSkipDir(model.ProfileFullFS, "proc") {
		t.Fatalf("expected fullfs profile to skip proc")
	}
	if ThresholdExceeded([]model.Finding{{Severity: model.SeverityLow}}, model.SeverityHigh, "") {
		t.Fatalf("low severity should not exceed high threshold")
	}
	if !ThresholdExceeded([]model.Finding{{Severity: model.SeverityCritical}}, model.SeverityHigh, "") {
		t.Fatalf("critical severity should exceed high threshold")
	}
}

func TestWorldWritableArtifactFinding(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "mcp.json")
	if err := os.WriteFile(path, []byte(`{"name":"x"}`), 0o666); err != nil {
		t.Fatalf("write file failed: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	finding, ok := WorldWritableArtifactFinding(path, "mcp.json", info, true)
	if !ok {
		t.Fatalf("expected world-writable sensitive artifact finding")
	}
	if finding.RuleID != "SKN-PROT-001" {
		t.Fatalf("unexpected rule id: %s", finding.RuleID)
	}

	nonSensitivePath := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(nonSensitivePath, []byte("x"), 0o666); err != nil {
		t.Fatalf("write non-sensitive file failed: %v", err)
	}
	_ = os.Chmod(nonSensitivePath, 0o666)
	nonSensitiveInfo, _ := os.Stat(nonSensitivePath)
	if _, ok := WorldWritableArtifactFinding(nonSensitivePath, "notes.txt", nonSensitiveInfo, true); ok {
		t.Fatalf("did not expect non-sensitive file to produce hardening finding")
	}
}

func TestScanFileAddsPathAndPermissionHeuristics(t *testing.T) {
	root := t.TempDir()
	longA := strings.Repeat("a", 170)
	longB := strings.Repeat("b", 170)
	longC := strings.Repeat("c", 170)
	path := filepath.Join(root, longA, longB, longC, "skill.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("harmless content"), 0o666); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	pathRules := []model.Rule{
		{
			ID:          "PATH-TEST-1",
			Title:       "skill manifest",
			Description: "path rule",
			Category:    "test",
			Mitre:       "T1",
			Severity:    model.SeverityInfo,
			Pattern:     `(?i)(^|/)skill\.md$`,
			Target:      model.TargetPath,
			RE:          regexp.MustCompile(`(?i)(^|/)skill\.md$`),
		},
	}

	result := ScanSingleFile(path, root, pathRules, nil, ScanFileOptions{
		MaxBytes:           DefaultMaxBytes,
		MaxFindingsPerFile: 50,
		ScanStyle:          model.ScanStylePattern,
		ThreatMode:         model.ThreatModeAll,
		PolicyChecks:       true,
		RedactSecrets:      true,
	})
	if result.Err != nil {
		t.Fatalf("scanFile failed: %v", result.Err)
	}
	if result.Scanned != 1 {
		t.Fatalf("expected scanned=1, got %d", result.Scanned)
	}
	seen := make(map[string]struct{}, len(result.Findings))
	for _, finding := range result.Findings {
		seen[finding.RuleID] = struct{}{}
	}
	if _, ok := seen["ATK-DEF-EBPF-001"]; !ok {
		t.Fatalf("expected long-path heuristic finding")
	}
	if _, ok := seen["SKN-PROT-001"]; !ok {
		t.Fatalf("expected world-writable artifact finding")
	}
}

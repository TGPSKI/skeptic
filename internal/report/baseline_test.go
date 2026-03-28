package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestWriteAndLoadJSONReport(t *testing.T) {
	root := t.TempDir()
	reportPath := filepath.Join(root, "baseline", "report.json")
	original := model.Report{
		Profile: model.ProfileRepo,
		Findings: []model.Finding{
			{RuleID: "RULE-1", File: "a.txt", Line: 4, Severity: model.SeverityHigh},
		},
	}

	if err := WriteJSONReport(reportPath, original); err != nil {
		t.Fatalf("WriteJSONReport failed: %v", err)
	}

	loaded, err := LoadBaselineReport(reportPath)
	if err != nil {
		t.Fatalf("LoadBaselineReport failed: %v", err)
	}
	if len(loaded.Findings) != 1 || loaded.Findings[0].RuleID != "RULE-1" {
		t.Fatalf("unexpected loaded baseline report: %+v", loaded)
	}
}

func TestLoadBaselineReportInvalidJSON(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "bad.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0o644); err != nil {
		t.Fatalf("write invalid json: %v", err)
	}
	if _, err := LoadBaselineReport(path); err == nil {
		t.Fatalf("expected invalid JSON to fail")
	}
}

func TestFindingIdentityKey(t *testing.T) {
	f := model.Finding{RuleID: " RULE ", File: " a.txt ", Line: 9, Match: "needle"}
	h := sha256.Sum256([]byte(f.Match))
	want := fmt.Sprintf("%s|%s|%s", f.RuleID, f.File, hex.EncodeToString(h[:8]))
	if got := FindingIdentityKey(f); got != want {
		t.Fatalf("FindingIdentityKey: got %q want %q", got, want)
	}
}

func TestFindingIdentityKeyV1(t *testing.T) {
	f := model.Finding{RuleID: " RULE ", File: " a.txt ", Line: 9, Match: "ignored"}
	if got, want := FindingIdentityKeyV1(f), " RULE | a.txt |9"; got != want {
		t.Fatalf("FindingIdentityKeyV1: got %q want %q", got, want)
	}
}

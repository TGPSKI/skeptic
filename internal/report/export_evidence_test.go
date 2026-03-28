package report

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestExportEvidenceBasic(t *testing.T) {
	dir := t.TempDir()
	report := model.Report{
		Findings: []model.Finding{
			{RuleID: "TEST-001", File: "test.py", Line: 10, Match: "test match", Severity: model.SeverityHigh},
		},
		FindingsBySeverity: map[string]int{"high": 1},
		ScannedFiles:       5,
	}
	reportJSON, _ := json.Marshal(report)
	reportPath := filepath.Join(dir, "report.json")
	os.WriteFile(reportPath, reportJSON, 0o644)

	outPath := filepath.Join(dir, "evidence.tar.gz")
	var stdout, stderr strings.Builder
	code := RunExportEvidence(&stdout, &stderr, ExportEvidenceOptions{
		ReportPath: reportPath,
		OutPath:    outPath,
	})
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gr)
	files := make(map[string]bool)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		files[hdr.Name] = true
	}
	for _, name := range []string{"findings.json", "manifest.json", "snippets.json"} {
		if !files[name] {
			t.Errorf("missing %s in bundle", name)
		}
	}
}

func TestExportEvidenceMissingReport(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunExportEvidence(&stdout, &stderr, ExportEvidenceOptions{})
	if code == 0 {
		t.Fatal("expected non-zero exit for missing report path")
	}
}

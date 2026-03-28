package correlation

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestFilePathRelativeToRepo(t *testing.T) {
	repo := "/project/repo"
	rel, ok := filePathRelativeToRepo(repo, "src/a.go")
	if !ok || rel != filepath.Join("src", "a.go") {
		t.Fatalf("unexpected rel %q ok=%v", rel, ok)
	}
	if _, ok := filePathRelativeToRepo(repo, "/other/outside.go"); ok {
		t.Fatal("expected outside path to be rejected")
	}
}

func TestIsHighSeverityFinding(t *testing.T) {
	tests := []struct {
		sev  model.Severity
		want bool
	}{
		{model.SeverityCritical, true},
		{model.SeverityHigh, true},
		{model.SeverityMedium, false},
		{model.SeverityLow, false},
		{model.SeverityInfo, false},
	}
	for _, tt := range tests {
		if got := isHighSeverityFinding(model.Finding{Severity: tt.sev}); got != tt.want {
			t.Errorf("severity %v: got %v want %v", tt.sev, got, tt.want)
		}
	}
}

func TestCorrelateByGitHistoryEmpty(t *testing.T) {
	if out := CorrelateByGitHistory(nil, t.TempDir()); out != nil {
		t.Fatalf("expected nil for empty findings, got %#v", out)
	}
}

func TestCorrelateByGitHistoryNonRepoReturnsNil(t *testing.T) {
	dir := t.TempDir()
	findings := []model.Finding{
		{RuleID: "R1", File: filepath.Join(dir, "a.go"), Severity: model.SeverityHigh},
	}
	if out := CorrelateByGitHistory(findings, dir); out != nil {
		t.Fatalf("expected nil when repo root is not a git checkout, got %#v", out)
	}
}

func TestCorrelateByGitHistoryGitNotInPath(t *testing.T) {
	if orig, ok := os.LookupEnv("PATH"); ok {
		t.Setenv("PATH", "")
		defer os.Setenv("PATH", orig)
	} else {
		t.Setenv("PATH", "")
	}
	findings := []model.Finding{
		{RuleID: "R1", File: "/tmp/x", Severity: model.SeverityHigh},
	}
	if out := CorrelateByGitHistory(findings, "/"); out != nil {
		t.Fatalf("expected nil when git is not in PATH, got %#v", out)
	}
}

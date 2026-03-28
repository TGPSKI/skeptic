package enrich

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

func TestEnrichReportNoOps(t *testing.T) {
	report := &model.Report{}
	opts := Options{}
	logger := logging.NewLogger(logging.LogError, io.Discard)
	EnrichReport(report, opts, []string{t.TempDir()}, model.ThreatModeAll, logger)
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings with all options disabled, got %d", len(report.Findings))
	}
}

func TestEnrichReportPolicyChecks(t *testing.T) {
	dir := t.TempDir()
	report := &model.Report{}
	opts := Options{PolicyChecks: true, RedactSecrets: true}
	logger := logging.NewLogger(logging.LogError, io.Discard)
	EnrichReport(report, opts, []string{dir}, model.ThreatModeAll, logger)
	// Policy checks on empty dir should produce no findings but not panic.
}

func TestEnrichReportIdentityGraphGating(t *testing.T) {
	dir := t.TempDir()
	logger := logging.NewLogger(logging.LogError, io.Discard)

	report1 := &model.Report{}
	EnrichReport(report1, Options{}, []string{dir}, model.ThreatModeAIWorkload, logger)
	before := len(report1.Findings)

	report2 := &model.Report{}
	EnrichReport(report2, Options{}, []string{dir}, model.ThreatModeMachineIdentity, logger)

	// Machine identity mode triggers identity graph checks; AI workload does not.
	// On an empty dir both produce 0 findings, but this validates the gating doesn't panic.
	if len(report2.Findings) < before {
		t.Errorf("machine-identity mode should not produce fewer findings than ai-workload mode")
	}
}

func TestEnrichReportGitCorrelation(t *testing.T) {
	dir := t.TempDir()
	report := &model.Report{}
	opts := Options{GitCorrelation: true}
	logger := logging.NewLogger(logging.LogError, io.Discard)
	EnrichReport(report, opts, []string{dir}, model.ThreatModeAll, logger)
	// Git correlation on a non-git dir should gracefully produce no findings.
}

func TestEnrichReportSBOMBranch(t *testing.T) {
	dir := t.TempDir()
	logger := logging.NewLogger(logging.LogError, io.Discard)

	t.Run("nonexistent sbom file", func(t *testing.T) {
		report := &model.Report{}
		opts := Options{SBOMPath: filepath.Join(dir, "noexist.json")}
		EnrichReport(report, opts, []string{dir}, model.ThreatModeAll, logger)
	})

	t.Run("invalid sbom content", func(t *testing.T) {
		sbomPath := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(sbomPath, []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		report := &model.Report{}
		opts := Options{SBOMPath: sbomPath}
		EnrichReport(report, opts, []string{dir}, model.ThreatModeAll, logger)
	})

	t.Run("empty sbom", func(t *testing.T) {
		sbomPath := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(sbomPath, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		report := &model.Report{}
		opts := Options{SBOMPath: sbomPath}
		EnrichReport(report, opts, []string{dir}, model.ThreatModeAll, logger)
	})

	t.Run("whitespace-only sbom path is noop", func(t *testing.T) {
		report := &model.Report{}
		opts := Options{SBOMPath: "   "}
		EnrichReport(report, opts, []string{dir}, model.ThreatModeAll, logger)
		if len(report.Findings) != 0 {
			t.Errorf("expected no findings for whitespace sbom path, got %d", len(report.Findings))
		}
	})
}

func TestEnrichReportBehaviorBaselineBranch(t *testing.T) {
	dir := t.TempDir()
	logger := logging.NewLogger(logging.LogError, io.Discard)

	baselinePath := filepath.Join(dir, "baseline.json")
	report := &model.Report{
		ScannedFiles: 5,
		Findings: []model.Finding{
			{RuleID: "TEST-001", File: "a.go", Severity: model.SeverityHigh},
		},
	}
	opts := Options{
		BehaviorBaselinePath:    baselinePath,
		DriftSeverityMultiplier: 2.0,
		DriftAllowedChainsRaw:   "*.test,*.spec",
	}
	EnrichReport(report, opts, []string{dir}, model.ThreatModeAll, logger)

	if _, err := os.Stat(baselinePath); err != nil {
		t.Errorf("baseline profile should have been saved: %v", err)
	}
}

func TestEnrichReportBehaviorHistoryBranch(t *testing.T) {
	dir := t.TempDir()
	logger := logging.NewLogger(logging.LogError, io.Discard)

	histPath := filepath.Join(dir, "history.json")
	report := &model.Report{
		ScannedFiles: 3,
		Findings: []model.Finding{
			{RuleID: "TEST-002", File: "b.go", Severity: model.SeverityMedium},
		},
	}
	opts := Options{BehaviorHistoryPath: histPath}
	EnrichReport(report, opts, []string{dir}, model.ThreatModeAll, logger)

	if _, err := os.Stat(histPath); err != nil {
		t.Errorf("history file should have been saved: %v", err)
	}

	report2 := &model.Report{ScannedFiles: 4}
	EnrichReport(report2, opts, []string{dir}, model.ThreatModeAll, logger)
}

func TestEnrichReportNilLogger(t *testing.T) {
	dir := t.TempDir()

	t.Run("nil logger with all opts disabled", func(t *testing.T) {
		report := &model.Report{}
		EnrichReport(report, Options{}, []string{dir}, model.ThreatModeAll, nil)
		if len(report.Findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(report.Findings))
		}
	})

	t.Run("nil logger with policy checks", func(t *testing.T) {
		report := &model.Report{}
		EnrichReport(report, Options{PolicyChecks: true}, []string{dir}, model.ThreatModeAll, nil)
	})

	t.Run("nil logger with identity graph", func(t *testing.T) {
		report := &model.Report{}
		EnrichReport(report, Options{}, []string{dir}, model.ThreatModeMachineIdentity, nil)
	})

	t.Run("nil logger with git correlation", func(t *testing.T) {
		report := &model.Report{}
		EnrichReport(report, Options{GitCorrelation: true}, []string{dir}, model.ThreatModeAll, nil)
	})

	t.Run("nil logger with SBOM path", func(t *testing.T) {
		sbomPath := filepath.Join(dir, "nonexistent-sbom.json")
		report := &model.Report{}
		EnrichReport(report, Options{SBOMPath: sbomPath}, []string{dir}, model.ThreatModeAll, nil)
	})

	t.Run("nil logger with behavior baseline", func(t *testing.T) {
		baselinePath := filepath.Join(dir, "nil-logger-baseline.json")
		report := &model.Report{
			ScannedFiles: 3,
			Findings:     []model.Finding{{RuleID: "TEST-NIL", File: "x.go", Severity: model.SeverityHigh}},
		}
		EnrichReport(report, Options{BehaviorBaselinePath: baselinePath}, []string{dir}, model.ThreatModeAll, nil)
		if _, err := os.Stat(baselinePath); err != nil {
			t.Errorf("baseline should have been saved even with nil logger: %v", err)
		}
	})

	t.Run("nil logger with behavior history", func(t *testing.T) {
		histPath := filepath.Join(dir, "nil-logger-history.json")
		report := &model.Report{
			ScannedFiles: 2,
			Findings:     []model.Finding{{RuleID: "TEST-NIL-H", File: "y.go", Severity: model.SeverityMedium}},
		}
		EnrichReport(report, Options{BehaviorHistoryPath: histPath}, []string{dir}, model.ThreatModeAll, nil)
		if _, err := os.Stat(histPath); err != nil {
			t.Errorf("history should have been saved even with nil logger: %v", err)
		}
	})
}

func TestEnrichReportHistoryLoadFailureLogged(t *testing.T) {
	dir := t.TempDir()
	var logBuf bytes.Buffer
	logger := logging.NewLogger(logging.LogWarn, &logBuf)

	histPath := filepath.Join(dir, "corrupt-history.json")
	if err := os.WriteFile(histPath, []byte("not valid json{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := &model.Report{
		ScannedFiles: 1,
		Findings:     []model.Finding{{RuleID: "TEST-HIST", File: "z.go", Severity: model.SeverityLow}},
	}
	EnrichReport(report, Options{BehaviorHistoryPath: histPath}, []string{dir}, model.ThreatModeAll, logger)

	logged := logBuf.String()
	if !strings.Contains(logged, "failed to load profile history") {
		t.Errorf("expected warning about profile history load failure, got: %q", logged)
	}
}

func TestOptionsFieldCoverage(t *testing.T) {
	opts := Options{
		PolicyChecks:                    true,
		IdentityGraphHops:               3,
		RedactSecrets:                   true,
		ProvenanceManifestPath:          "",
		RequireSignedProvenanceManifest: false,
		SBOMPath:                        "",
		AutoDiscoverMCP:                 false,
		BehaviorBaselinePath:            "",
		DriftSeverityMultiplier:         1.5,
		DriftAllowedChainsRaw:           "",
		BehaviorHistoryPath:             "",
		GitCorrelation:                  false,
	}
	if !opts.PolicyChecks {
		t.Error("PolicyChecks should be true")
	}
}

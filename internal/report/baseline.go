package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TGPSKI/skeptic/internal/model"
)

// LoadBaselineReport reads a prior JSON report used for finding diffing.
func LoadBaselineReport(path string) (model.Report, error) {
	abs, err := filepath.Abs(model.ExpandHomePath(path))
	if err != nil {
		return model.Report{}, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return model.Report{}, err
	}
	var report model.Report
	if err := json.Unmarshal(data, &report); err != nil {
		return model.Report{}, err
	}
	return report, nil
}

// WriteJSONReport writes a JSON report file and creates parent directories when
// needed. The write is atomic, so a concurrent reader — a later --baseline run,
// or a daemon serving the last report — never sees a truncated file.
func WriteJSONReport(path string, report model.Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return WriteFileAtomic(path, data, 0o644)
}

// FindingIdentityKey builds a stable identity for baseline comparisons from rule id, file path,
// and a short SHA256 prefix of the match text (line-independent).
func FindingIdentityKey(f model.Finding) string {
	h := sha256.Sum256([]byte(f.Match))
	matchPrefix := hex.EncodeToString(h[:8])
	return fmt.Sprintf("%s|%s|%s", f.RuleID, f.File, matchPrefix)
}

// FindingIdentityKeyV1 is the legacy identity (rule id, file, line) for migrating old baselines.
func FindingIdentityKeyV1(f model.Finding) string {
	return fmt.Sprintf("%s|%s|%d", f.RuleID, f.File, f.Line)
}

func summarizeFindings(findings []model.Finding) map[string]int {
	out := map[string]int{
		string(model.SeverityCritical): 0,
		string(model.SeverityHigh):     0,
		string(model.SeverityMedium):   0,
		string(model.SeverityLow):      0,
		string(model.SeverityInfo):     0,
	}
	for _, finding := range findings {
		out[string(finding.Severity)]++
	}
	return out
}

// ApplyBaselineDiff annotates current findings against baseline identity keys.
func ApplyBaselineDiff(report *model.Report, baseline model.Report, diffOnly bool) {
	if report == nil {
		return
	}

	baselineSet := make(map[string]struct{}, len(baseline.Findings))
	for _, finding := range baseline.Findings {
		baselineSet[FindingIdentityKey(finding)] = struct{}{}
	}

	currentSet := make(map[string]struct{}, len(report.Findings))
	newCount := 0
	unchangedCount := 0
	for i := range report.Findings {
		key := FindingIdentityKey(report.Findings[i])
		currentSet[key] = struct{}{}
		if _, ok := baselineSet[key]; ok {
			report.Findings[i].BaselineState = "unchanged"
			unchangedCount++
			continue
		}
		report.Findings[i].BaselineState = "new"
		newCount++
	}

	resolvedCount := 0
	for key := range baselineSet {
		if _, ok := currentSet[key]; ok {
			continue
		}
		resolvedCount++
	}

	report.NewFindings = newCount
	report.UnchangedFindings = unchangedCount
	report.ResolvedFindings = resolvedCount
	report.DiffOnly = diffOnly

	if diffOnly {
		filtered := make([]model.Finding, 0, len(report.Findings))
		for _, finding := range report.Findings {
			if finding.BaselineState != "new" {
				continue
			}
			filtered = append(filtered, finding)
		}
		report.Findings = filtered
	}
	report.FindingsBySeverity = summarizeFindings(report.Findings)
}

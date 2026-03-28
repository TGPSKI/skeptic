package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// WriteTextReport renders human-readable report output with scan metadata context.
func WriteTextReport(out io.Writer, report model.Report) {
	if len(report.TargetPaths) <= 1 {
		target := report.TargetPath
		if target == "" && len(report.TargetPaths) == 1 {
			target = report.TargetPaths[0]
		}
		fmt.Fprintf(out, "skeptic target: %s\n", target)
	} else {
		fmt.Fprintf(out, "skeptic targets (%d):\n", len(report.TargetPaths))
		for _, target := range report.TargetPaths {
			fmt.Fprintf(out, "  - %s\n", target)
		}
	}
	fmt.Fprintf(out, "profile: %s\n", report.Profile)
	fmt.Fprintf(out, "scan style: %s\n", report.ScanStyle)
	fmt.Fprintf(out, "threat mode: %s\n", report.ThreatMode)
	fmt.Fprintf(out, "policy checks: %t\n", report.PolicyChecks)
	if report.RulesetHash != "" {
		fmt.Fprintf(out, "ruleset hash: %s\n", report.RulesetHash)
	}
	if report.Incremental {
		fmt.Fprintln(out, "incremental mode: enabled")
		if report.StateCachePath != "" {
			fmt.Fprintf(out, "state cache: %s\n", report.StateCachePath)
		}
		if report.CacheSkippedFiles > 0 {
			fmt.Fprintf(out, "cache-skipped files: %d\n", report.CacheSkippedFiles)
		}
	}
	fmt.Fprintf(out, "scanned files: %d (skipped: %d)\n", report.ScannedFiles, report.SkippedFiles)
	if report.PermissionErrors > 0 {
		fmt.Fprintf(out, "permission errors skipped: %d\n", report.PermissionErrors)
	}
	if report.MaxFilesReached {
		fmt.Fprintf(out, "scan limit reached: max-files=%d\n", report.MaxFiles)
	}
	if report.MaxFindingsReached {
		fmt.Fprintf(out, "finding limit reached: max-findings=%d (dropped=%d)\n", report.MaxFindings, report.DroppedFindings)
	}
	if report.RedactedMatches {
		fmt.Fprintln(out, "match redaction: enabled")
	}
	if report.BaselinePath != "" {
		fmt.Fprintf(out, "baseline: %s\n", report.BaselinePath)
		fmt.Fprintf(
			out,
			"baseline diff: new=%d unchanged=%d resolved=%d (diff-only=%t)\n",
			report.NewFindings,
			report.UnchangedFindings,
			report.ResolvedFindings,
			report.DiffOnly,
		)
	}
	fmt.Fprintf(
		out,
		"findings: critical=%d high=%d medium=%d low=%d info=%d\n",
		report.FindingsBySeverity[string(model.SeverityCritical)],
		report.FindingsBySeverity[string(model.SeverityHigh)],
		report.FindingsBySeverity[string(model.SeverityMedium)],
		report.FindingsBySeverity[string(model.SeverityLow)],
		report.FindingsBySeverity[string(model.SeverityInfo)],
	)
	if report.RiskScore > 0 {
		fmt.Fprintf(out, "risk score: %d/100\n", report.RiskScore)
	}
	fmt.Fprintln(out)

	if len(report.Findings) == 0 {
		fmt.Fprintln(out, "no findings")
		return
	}

	defCnt := report.FindingsByConfidence["definitive"]
	heuCnt := report.FindingsByConfidence["heuristic"]
	corCnt := report.FindingsByConfidence["correlated"]
	modeStr := string(report.Mode)
	if modeStr == "" {
		modeStr = "developer"
	}
	fmt.Fprintf(
		out,
		"Trust assessment: %d definitive, %d heuristic, %d correlated\nMode: %s | Files scanned: %d | Risk score: %d/100\n---\n",
		defCnt, heuCnt, corCnt, modeStr, report.ScannedFiles, report.RiskScore,
	)

	var suppressedCount int
	for _, finding := range report.Findings {
		if finding.Suppressed {
			suppressedCount++
			continue
		}
		location := finding.File
		if finding.Line > 0 {
			location = fmt.Sprintf("%s:%d", finding.File, finding.Line)
		}
		severityLabel := strings.ToUpper(string(finding.Severity))
		if finding.BaselineState != "" {
			severityLabel = severityLabel + "/" + strings.ToUpper(finding.BaselineState)
		}
		confLabel := strings.ToUpper(string(finding.ConfidenceClass))
		if confLabel == "" {
			confLabel = "HEURISTIC"
		}
		categoryDisplay := finding.Category
		if categoryDisplay == "trust-laundering" {
			categoryDisplay = "trust-laundering (low-review surface)"
		}
		fmt.Fprintf(
			out,
			"[%s/%s] %s %s\n  file: %s\n  category: %s\n  mitre: %s\n  match: %s\n",
			severityLabel,
			confLabel,
			finding.RuleID,
			finding.Title,
			location,
			categoryDisplay,
			finding.Mitre,
			finding.Match,
		)
		if finding.Remediation != "" && (finding.Severity == model.SeverityCritical || finding.Severity == model.SeverityHigh) {
			fmt.Fprintf(out, "  fix: %s\n", finding.Remediation)
		}
		fmt.Fprintln(out)
	}

	if suppressedCount > 0 {
		fmt.Fprintf(out, "waived: %d findings suppressed\n", suppressedCount)
	}
	if report.ThresholdExceeded {
		fmt.Fprintf(out, "threshold exceeded (fail-on=%s)\n", report.FailOn)
	}
}

package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// WriteMarkdown renders a scan report as a GitHub-flavored Markdown summary
// suitable for PR comments or CI job summaries.
func WriteMarkdown(out io.Writer, report model.Report) {
	fmt.Fprintln(out, "## skeptic scan results")
	fmt.Fprintln(out)

	crit := report.FindingsBySeverity[string(model.SeverityCritical)]
	high := report.FindingsBySeverity[string(model.SeverityHigh)]
	med := report.FindingsBySeverity[string(model.SeverityMedium)]
	low := report.FindingsBySeverity[string(model.SeverityLow)]
	info := report.FindingsBySeverity[string(model.SeverityInfo)]

	fmt.Fprintln(out, "| Severity | Count |")
	fmt.Fprintln(out, "|----------|------:|")
	fmt.Fprintf(out, "| Critical | %d |\n", crit)
	fmt.Fprintf(out, "| High | %d |\n", high)
	fmt.Fprintf(out, "| Medium | %d |\n", med)
	fmt.Fprintf(out, "| Low | %d |\n", low)
	fmt.Fprintf(out, "| Info | %d |\n", info)
	fmt.Fprintf(out, "| **Total** | **%d** |\n", len(report.Findings))
	fmt.Fprintln(out)

	if report.RiskScore > 0 {
		fmt.Fprintf(out, "**Risk score: %d / 100**\n\n", report.RiskScore)
	}

	limit := 10
	if len(report.Findings) < limit {
		limit = len(report.Findings)
	}
	if limit > 0 {
		fmt.Fprintln(out, "### Top findings")
		fmt.Fprintln(out)
		mdDef := report.FindingsByConfidence["definitive"]
		mdHeu := report.FindingsByConfidence["heuristic"]
		mdCor := report.FindingsByConfidence["correlated"]
		mdMode := string(report.Mode)
		if mdMode == "" {
			mdMode = "developer"
		}
		fmt.Fprintf(out,
			"**Trust assessment:** %d definitive, %d heuristic, %d correlated  \n**Mode:** %s | **Files scanned:** %d | **Risk score:** %d/100\n\n",
			mdDef, mdHeu, mdCor, mdMode, report.ScannedFiles, report.RiskScore,
		)
		fmt.Fprintln(out, "| Severity | Confidence | Rule | File | Title |")
		fmt.Fprintln(out, "|----------|------------|------|------|-------|")
		for _, f := range report.Findings[:limit] {
			file := f.File
			if f.Line > 0 {
				file = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			confCol := strings.ToUpper(string(f.ConfidenceClass))
			if confCol == "" {
				confCol = "HEURISTIC"
			}
			// A waived finding stays in the report, so the table has to say so.
			// Rendering it identically to a live one reads as an open finding
			// that nobody acted on.
			title := f.Title
			ruleDisplay := f.RuleID
			if len(f.RelatedRuleIDs) > 0 {
				ruleDisplay = fmt.Sprintf("%s (+%d related)", f.RuleID, len(f.RelatedRuleIDs))
			}
			if f.Suppressed {
				title = "~~" + f.Title + "~~ (waived)"
			}
			fmt.Fprintf(out, "| %s | %s | `%s` | `%s` | %s |\n",
				strings.ToUpper(string(f.Severity)),
				confCol,
				ruleDisplay,
				file,
				title,
			)
		}
		fmt.Fprintln(out)
	}

	fileCounts := markdownFileSummary(report.Findings)
	if len(fileCounts) > 0 {
		fmt.Fprintln(out, "### Files with most findings")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "| File | Findings |")
		fmt.Fprintln(out, "|------|--------:|")
		limit := 10
		if len(fileCounts) < limit {
			limit = len(fileCounts)
		}
		for _, fc := range fileCounts[:limit] {
			fmt.Fprintf(out, "| `%s` | %d |\n", fc.file, fc.count)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "Files scanned: %d | Skipped: %d", report.ScannedFiles, report.SkippedFiles)
	if report.CacheSkippedFiles > 0 {
		fmt.Fprintf(out, " | Cache hits: %d", report.CacheSkippedFiles)
	}
	if report.PermissionErrors > 0 {
		fmt.Fprintf(out, " | Permission errors: %d", report.PermissionErrors)
	}
	fmt.Fprintln(out)

	if report.ThresholdExceeded {
		fmt.Fprintf(out, "\n**Threshold exceeded** (fail-on=%s)\n", report.FailOn)
	}
}

type fileCount struct {
	file  string
	count int
}

func markdownFileSummary(findings []model.Finding) []fileCount {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.File]++
	}
	result := make([]fileCount, 0, len(counts))
	for file, count := range counts {
		result = append(result, fileCount{file: file, count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].count != result[j].count {
			return result[i].count > result[j].count
		}
		return result[i].file < result[j].file
	})
	return result
}

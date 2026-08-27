package report

import (
	"encoding/json"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// WriteSARIFReport renders the scan report using SARIF 2.1.0 schema.
func WriteSARIFReport(out io.Writer, report model.Report) error {
	payload := map[string]any{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []any{
			BuildSARIFRun(report),
		},
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

// BuildSARIFRun converts findings into SARIF rules/results payloads.
func BuildSARIFRun(report model.Report) map[string]any {
	rulesByID := make(map[string]map[string]any, len(report.Findings))
	results := make([]any, 0, len(report.Findings))
	for _, finding := range report.Findings {
		// A waived finding produces no SARIF result.
		//
		// SARIF's consumer here is GitHub code scanning, which turns every
		// result into an alert and has no way to express "found and accepted".
		// result.suppressions is not among the properties GitHub supports, so
		// emitting it — as #97 did — is spec-correct and discarded: 50
		// suppressions uploaded, 49 alerts opened (#98).
		//
		// The complete record stays in the JSON report, which carries
		// suppressed and suppression_reason, and in the text and markdown
		// reports, which label waived findings in place.
		if finding.Suppressed {
			continue
		}
		confClass := string(finding.ConfidenceClass)
		if confClass == "" {
			confClass = "heuristic"
		}
		if _, exists := rulesByID[finding.RuleID]; !exists {
			ruleDesc := map[string]any{
				"id":   finding.RuleID,
				"name": strings.TrimSpace(finding.Title),
				"shortDescription": map[string]any{
					"text": strings.TrimSpace(finding.Title),
				},
				"fullDescription": map[string]any{
					"text": strings.TrimSpace(finding.Description),
				},
				"properties": map[string]any{
					"severity":         strings.ToLower(string(finding.Severity)),
					"category":         strings.TrimSpace(finding.Category),
					"mitre":            strings.TrimSpace(finding.Mitre),
					"confidence_class": confClass,
				},
			}
			if finding.Remediation != "" {
				ruleDesc["help"] = map[string]any{
					"text": finding.Remediation,
				}
			}
			rulesByID[finding.RuleID] = ruleDesc
		}

		artifactLocation := map[string]any{"uri": finding.File}
		if uri, based := sarifArtifactURI(report, finding.File); uri != "" {
			artifactLocation["uri"] = uri
			if based {
				artifactLocation["uriBaseId"] = "%SRCROOT%"
			}
		}
		location := map[string]any{
			"physicalLocation": map[string]any{
				"artifactLocation": artifactLocation,
			},
		}
		if finding.Line > 0 {
			location["physicalLocation"].(map[string]any)["region"] = map[string]any{ //nolint:errcheck // structure is self-built
				"startLine": finding.Line,
			}
		}

		resultProperties := map[string]any{
			"match":            finding.Match,
			"severity":         strings.ToLower(string(finding.Severity)),
			"category":         finding.Category,
			"mitre":            finding.Mitre,
			"confidence_class": confClass,
		}
		result := map[string]any{
			"ruleId": finding.RuleID,
			"level":  SARIFLevelFromSeverity(finding.Severity),
			"message": map[string]any{
				"text": strings.TrimSpace(finding.Title),
			},
			"locations": []any{location},
			"partialFingerprints": map[string]any{
				"skepticFindingKey": FindingIdentityKey(finding),
			},
			"properties": resultProperties,
		}
		if len(finding.RelatedRuleIDs) > 0 {
			resultProperties["related_rule_ids"] = finding.RelatedRuleIDs
		}
		if finding.BaselineState != "" {
			result["baselineState"] = finding.BaselineState
		}
		results = append(results, result)
	}

	ruleList := make([]map[string]any, 0, len(rulesByID))
	for _, rule := range rulesByID {
		ruleList = append(ruleList, rule)
	}
	slices.SortFunc(ruleList, func(a, b map[string]any) int {
		return strings.Compare(a["id"].(string), b["id"].(string)) //nolint:errcheck // structure is self-built
	})

	toolVersion := strings.TrimSpace(report.ToolVersion)
	if toolVersion == "" {
		toolVersion = "unknown"
	}
	invocation := map[string]any{
		"executionSuccessful": true,
	}
	if s := strings.TrimSpace(report.GeneratedAt); s != "" {
		invocation["startTimeUtc"] = s
	}
	if e := strings.TrimSpace(report.ScanCompletedAt); e != "" {
		invocation["endTimeUtc"] = e
	} else if s := strings.TrimSpace(report.GeneratedAt); s != "" {
		invocation["endTimeUtc"] = s
	}

	driver := map[string]any{
		"name":    "skeptic",
		"version": toolVersion,
		"rules":   ruleList,
	}
	if informationURI := strings.TrimSpace(report.ToolInformationURI); informationURI != "" {
		driver["informationUri"] = informationURI
	}
	run := map[string]any{
		"tool": map[string]any{
			"driver": driver,
		},
		"invocations": []any{invocation},
		"results":     results,
		"properties": map[string]any{
			"targetPaths":       report.TargetPaths,
			"profile":           report.Profile,
			"scanStyle":         report.ScanStyle,
			"threatMode":        report.ThreatMode,
			"policyChecks":      report.PolicyChecks,
			"scannedFiles":      report.ScannedFiles,
			"skippedFiles":      report.SkippedFiles,
			"cacheSkippedFiles": report.CacheSkippedFiles,
			"permissionErrors":  report.PermissionErrors,
			"newFindings":       report.NewFindings,
			"resolvedFindings":  report.ResolvedFindings,
			"unchangedFindings": report.UnchangedFindings,
			"failOn":            report.FailOn,
			"riskScore":         report.RiskScore,
			"thresholdExceeded": report.ThresholdExceeded,
		},
	}
	if base := strings.TrimSpace(report.SARIFBasePath); base != "" {
		run["originalUriBaseIds"] = map[string]any{
			"%SRCROOT%": map[string]any{"uri": fileURI(base, true)},
		}
	}
	return run
}

func sarifArtifactURI(report model.Report, findingFile string) (string, bool) {
	base := strings.TrimSpace(report.SARIFBasePath)
	if base == "" || strings.HasPrefix(findingFile, "(") {
		return filepath.ToSlash(findingFile), false
	}
	absFinding := findingFile
	if !filepath.IsAbs(absFinding) {
		if len(report.TargetPaths) != 1 {
			return filepath.ToSlash(findingFile), false
		}
		absFinding = filepath.Join(report.TargetPaths[0], findingFile)
	}
	rel, err := filepath.Rel(base, absFinding)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fileURI(absFinding, false), false
	}
	return filepath.ToSlash(rel), true
}

func fileURI(path string, directory bool) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String()
	if directory && !strings.HasSuffix(uri, "/") {
		uri += "/"
	}
	return uri
}

// SARIFLevelFromSeverity maps scanner severities into SARIF result levels.
func SARIFLevelFromSeverity(sev model.Severity) string {
	switch sev {
	case model.SeverityCritical, model.SeverityHigh:
		return "error"
	case model.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

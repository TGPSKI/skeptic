package report

import (
	"encoding/json"
	"io"
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

		location := map[string]any{
			"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{
					"uri": finding.File,
				},
			},
		}
		if finding.Line > 0 {
			location["physicalLocation"].(map[string]any)["region"] = map[string]any{ //nolint:errcheck // structure is self-built
				"startLine": finding.Line,
			}
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
			"properties": map[string]any{
				"match":            finding.Match,
				"severity":         strings.ToLower(string(finding.Severity)),
				"category":         finding.Category,
				"mitre":            finding.Mitre,
				"confidence_class": confClass,
			},
		}
		if finding.BaselineState != "" {
			result["baselineState"] = finding.BaselineState
		}
		// A waived finding stays in the report — suppress.ApplyWaivers marks it
		// rather than dropping it — so SARIF has to say it was suppressed.
		// Without this, code scanning opens an alert for every waived finding
		// and the check fails on a scan that exited 0 (#96).
		//
		// kind is "external" because the waiver lives in a separate file;
		// "inSource" is for an annotation in the code itself.
		if finding.Suppressed {
			suppression := map[string]any{"kind": "external"}
			if reason := strings.TrimSpace(finding.SuppressionReason); reason != "" {
				suppression["justification"] = reason
			}
			result["suppressions"] = []any{suppression}
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

	return map[string]any{
		"tool": map[string]any{
			"driver": map[string]any{
				"name":           "skeptic",
				"version":        toolVersion,
				"informationUri": "https://github.com/TGPSKI/skeptic",
				"rules":          ruleList,
			},
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

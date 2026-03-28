package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/suppress"
)

func scanRepoToolDescriptor() map[string]any {
	return map[string]any{
		"name":        "skeptic_scan_repo",
		"description": "Scan a local cloned repository path for exploit and supply-chain indicators.",
		"inputSchema": map[string]any{
			"type": "object",
			"required": []string{
				"repo_path",
			},
			"properties": map[string]any{
				"repo_path": map[string]any{
					"type":        "string",
					"description": "Absolute or relative path to a local repository clone.",
				},
				"require_git": map[string]any{
					"type":        "boolean",
					"description": "Require .git artifact to exist (default true).",
				},
				"scan_style": map[string]any{
					"type":        "string",
					"description": "Scan style: pattern (regex only), behavior (chain checks), or hybrid (both).",
					"enum":        []any{"pattern", "behavior", "hybrid"},
				},
				"threat_mode": map[string]any{
					"type":        "string",
					"description": "Threat focus filter: all (default), machine-identity, or ai-workload.",
					"enum":        []any{"all", "machine-identity", "ai-workload"},
				},
				"mode": map[string]any{
					"type":        "string",
					"description": "Operating mode: developer (default, trust audit), ir (incident response), deep (expert advisory).",
					"enum":        []any{"developer", "ir", "deep"},
				},
				"preset": map[string]any{
					"type":        "string",
					"description": "Apply a named preset that sets default scan options: quick, dev, ci, hunt, machine-identity, ai-workload.",
					"enum":        []any{"quick", "dev", "ci", "hunt", "machine-identity", "ai-workload"},
				},
				"profile": map[string]any{
					"type":        "string",
					"description": "Scan profile controlling file scope: repo (default), developer, container, fullfs.",
					"enum":        []any{"repo", "developer", "container", "fullfs"},
				},
				"fail_on": map[string]any{
					"type":        "string",
					"description": "Severity threshold for non-zero exit: none (default), info, low, medium, high, critical.",
					"enum":        []any{"none", "info", "low", "medium", "high", "critical"},
				},
				"include_rules": map[string]any{
					"type":        "string",
					"description": "Comma-separated rule IDs or prefixes to include (e.g. 'CI-,AGT-SKL-').",
				},
				"exclude_rules": map[string]any{
					"type":        "string",
					"description": "Comma-separated rule IDs or prefixes to exclude.",
				},
				"incremental": map[string]any{
					"type":        "boolean",
					"description": "Enable incremental scan using mtime+size cache (default false).",
				},
				"baseline": map[string]any{
					"type":        "string",
					"description": "Path to a baseline JSON report; only new findings are returned.",
				},
				"diff_only": map[string]any{
					"type":        "boolean",
					"description": "When baseline is set, return only new/changed findings (default false).",
				},
				"workers": map[string]any{
					"type":        "integer",
					"description": "Number of concurrent scan workers (default: CPU count).",
				},
				"max_files": map[string]any{
					"type":        "integer",
					"description": "Max scanned files (default 200000).",
				},
				"max_findings": map[string]any{
					"type":        "integer",
					"description": "Max findings retained (default 500).",
				},
				"sample_limit": map[string]any{
					"type":        "integer",
					"description": "Number of sample findings returned in response (default 25, max 200).",
				},
			},
		},
	}
}

func waiveToolDescriptor() map[string]any {
	return map[string]any{
		"name":        "skeptic_waive",
		"description": "Create SHA256-pinned waivers for scan findings on a specific file or rule.",
		"inputSchema": map[string]any{
			"type": "object",
			"required": []string{
				"repo_path",
				"reason",
			},
			"properties": map[string]any{
				"repo_path": map[string]any{
					"type":        "string",
					"description": "Absolute or relative path to the repository.",
				},
				"file": map[string]any{
					"type":        "string",
					"description": "Relative file path within repo to waive findings for. Omit to match all files.",
				},
				"rule": map[string]any{
					"type":        "string",
					"description": "Rule ID to waive. Omit to waive all rules on the matched file.",
				},
				"reason": map[string]any{
					"type":        "string",
					"description": "Required justification for the waiver.",
				},
			},
		},
	}
}

// MCPToolDescriptors returns all tools available in this server session.
func MCPToolDescriptors(allowTrigger bool, allowIngest bool, requireApproval bool) []map[string]any {
	tools := []map[string]any{
		{
			"name":        "skeptic_daemon_health",
			"description": "Fetch daemon health endpoint.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "skeptic_daemon_status",
			"description": "Fetch daemon runtime status.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			"name":        "skeptic_daemon_report",
			"description": "Fetch the latest daemon scan report. Returns the top N findings sorted by severity. Use top and min_severity to control response size.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"top": map[string]any{
						"type":        "integer",
						"description": "Maximum number of findings to return, sorted by severity descending (default 100).",
					},
					"min_severity": map[string]any{
						"type":        "string",
						"enum":        []string{"info", "low", "medium", "high", "critical"},
						"description": "Only return findings at or above this severity (default medium).",
					},
				},
			},
		},
		{
			"name":        "skeptic_daemon_metrics",
			"description": "Fetch daemon Prometheus-style metrics: scan counts, findings by severity, cache stats, rule count.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		scanRepoToolDescriptor(),
		waiveToolDescriptor(),
	}
	if allowTrigger {
		tools = append(tools, map[string]any{
			"name":        "skeptic_daemon_trigger_scan",
			"description": "Trigger an immediate daemon scan run (Phase B).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"reason": map[string]any{
						"type":        "string",
						"description": "Optional human-readable reason for audit trails.",
					},
				},
			},
		})
	}
	if allowIngest {
		tools = append(tools, map[string]any{
			"name":        "skeptic_ingest_url_to_rulepack",
			"description": "Parse a researcher URL and generate a local rule pack file.",
			"inputSchema": map[string]any{
				"type": "object",
				"required": []string{
					"source_url",
				},
				"properties": map[string]any{
					"source_url": map[string]any{
						"type":        "string",
						"description": "Threat-intel URL to ingest.",
					},
					"out_file": map[string]any{
						"type":        "string",
						"description": "Optional output filename (relative to MCP rules output dir).",
					},
					"allow_host": map[string]any{
						"type":        "string",
						"description": "Optional explicit host allowlist entry. Defaults to URL hostname.",
					},
					"allow_http": map[string]any{
						"type":        "boolean",
						"description": "Allow plaintext HTTP URLs (default false).",
					},
					"ecosystems": map[string]any{
						"type":        "string",
						"description": "Optional ecosystems CSV override.",
					},
					"min_severity": map[string]any{
						"type":        "string",
						"description": "Optional severity floor.",
					},
					"rule_quality": map[string]any{
						"type":        "string",
						"description": "Optional quality mode (off|warn|strict).",
					},
				},
			},
		})
		if requireApproval {
			tools = append(tools, map[string]any{
				"name":        "skeptic_approve_ingest",
				"description": "Approve a pending URL ingestion request.",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			})
		}
	}
	return tools
}

func handleDaemonQuery(name string, args map[string]any, state *MCPServerState) (map[string]any, error) {
	if state.DaemonClient == nil {
		return nil, errors.New("daemon client not configured; start the daemon or set --daemon-url")
	}
	var endpoint string
	switch name {
	case "skeptic_daemon_health":
		endpoint = "/health"
	case "skeptic_daemon_status":
		endpoint = "/status"
	case "skeptic_daemon_report":
		top := 100
		if v, ok := args["top"]; ok {
			switch n := v.(type) {
			case float64:
				top = int(n)
			case int:
				top = n
			}
		}
		minSev := "medium"
		if v := anyToString(args["min_severity"]); v != "" {
			minSev = v
		}
		endpoint = fmt.Sprintf("/report?top=%d&min_severity=%s", top, minSev)
	}
	body, err := state.DaemonClient.RequestJSON(context.Background(), http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return applyMCPToolNonce(mcpToolSuccess(body), args), nil
}

// HandleMCPToolsCall executes allowlisted tools with strict argument handling.
func HandleMCPToolsCall(paramsRaw json.RawMessage, state *MCPServerState) (map[string]any, error) {
	var params MCPToolsCallParams
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return nil, fmt.Errorf("invalid tools/call params: %w", err)
	}
	name := strings.TrimSpace(params.Name)
	if name == "" {
		return nil, errors.New("tools/call requires a tool name")
	}
	args := params.Arguments
	if args == nil {
		args = map[string]any{}
	}

	switch name {
	case "skeptic_daemon_health", "skeptic_daemon_status", "skeptic_daemon_report":
		return handleDaemonQuery(name, args, state)
	case "skeptic_daemon_metrics":
		if state.DaemonClient == nil {
			return nil, errors.New("daemon client not configured; start the daemon or set --daemon-url")
		}
		metricsText, err := state.DaemonClient.RequestText(context.Background(), http.MethodGet, "/metrics")
		if err != nil {
			return nil, err
		}
		return applyMCPToolNonce(mcpToolSuccess(map[string]any{
			"format":  "prometheus",
			"metrics": metricsText,
		}), args), nil
	case "skeptic_daemon_trigger_scan":
		if !state.AllowTrigger {
			return nil, errors.New("trigger tool disabled by server configuration")
		}
		if state.TriggerCooldown > 0 && !state.LastTriggerAt.IsZero() {
			elapsed := time.Since(state.LastTriggerAt)
			if elapsed < state.TriggerCooldown {
				remaining := state.TriggerCooldown - elapsed
				return nil, fmt.Errorf("trigger cooldown active: retry after %s", remaining.Round(time.Second))
			}
		}
		payload := map[string]any{}
		if reason := anyToString(args["reason"]); strings.TrimSpace(reason) != "" {
			payload["reason"] = reason
		}
		body, err := state.DaemonClient.RequestJSON(context.Background(), http.MethodPost, "/scan", payload)
		if err != nil {
			return nil, err
		}
		state.LastTriggerAt = time.Now()
		return applyMCPToolNonce(mcpToolSuccess(body), args), nil
	case "skeptic_ingest_url_to_rulepack":
		return handleIngestURLToRulepack(args, state)
	case "skeptic_approve_ingest":
		return handleApproveIngest(state)
	case "skeptic_scan_repo":
		result, err := MCPScanRepo(context.Background(), args, state)
		if err != nil {
			return nil, err
		}
		return applyMCPToolNonce(mcpToolSuccess(result), args), nil
	case "skeptic_waive":
		return handleWaive(args, state)
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

// latestReportResource returns a JSON string for the skeptic://report/latest resource.
// It reads from the durable daemon-report.json file in the skeptic data directory first;
// if unavailable it falls back to the live daemon HTTP endpoint. Either way the result
// is capped at 100 medium+ findings to keep the payload LLM-context-safe.
func latestReportResource(state *MCPServerState) string {
	const noReport = `{"status":"no_report_available"}`
	const top = 100
	minSevRank := model.SeverityWeight(model.SeverityMedium)

	summarise := func(r model.Report) string {
		// Filter and cap findings in place.
		var kept []model.Finding
		for _, f := range r.Findings {
			if model.SeverityWeight(f.Severity) >= minSevRank {
				kept = append(kept, f)
			}
		}
		sort.Slice(kept, func(i, j int) bool {
			return model.SeverityWeight(kept[i].Severity) > model.SeverityWeight(kept[j].Severity)
		})
		if len(kept) > top {
			kept = kept[:top]
		}
		r.Findings = kept
		out := map[string]any{
			"source":               "daemon-report.json",
			"scan_completed_at":    r.ScanCompletedAt,
			"target_paths":         r.TargetPaths,
			"scanned_files":        r.ScannedFiles,
			"findings_by_severity": r.FindingsBySeverity,
			"risk_score":           r.RiskScore,
			"mode":                 r.Mode,
			"incremental":          r.Incremental,
			"findings":             r.Findings,
			"note":                 fmt.Sprintf("top %d findings at medium+ severity; use skeptic_daemon_report tool for custom filters", top),
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return noReport
		}
		return string(b)
	}

	// Prefer the durable on-disk report — present even after daemon restart.
	if state.ReportFile != "" {
		if data, err := os.ReadFile(state.ReportFile); err == nil {
			var r model.Report
			if err := json.Unmarshal(data, &r); err == nil {
				return summarise(r)
			}
		}
	}

	// Fall back to the live daemon HTTP endpoint.
	if state.DaemonClient != nil {
		body, err := state.DaemonClient.RequestJSON(
			context.Background(), http.MethodGet,
			fmt.Sprintf("/report?top=%d&min_severity=medium", top), nil,
		)
		if err == nil {
			b, err := json.MarshalIndent(body, "", "  ")
			if err == nil {
				return string(b)
			}
		}
	}

	return noReport
}

// BuildTrustAssessment summarizes confidence-weighted risk for MCP scan consumers.
//
//nolint:gocyclo // multi-severity, multi-confidence aggregation is inherently branchy
func BuildTrustAssessment(report model.Report) map[string]any {
	defCount := report.FindingsByConfidence[string(model.ConfidenceDefinitive)]
	heurCount := report.FindingsByConfidence[string(model.ConfidenceHeuristic)]
	corCount := report.FindingsByConfidence[string(model.ConfidenceCorrelated)]

	mode := report.Mode
	if mode == "" {
		mode = model.ScanModeDeveloper
	}
	useGating := mode == model.ScanModeDeveloper

	verdict := "no_issues_found"
	for _, f := range report.Findings {
		if f.ConfidenceClass == model.ConfidenceDefinitive &&
			f.Severity == model.SeverityCritical &&
			(!useGating || model.IsGateEligible(f.RuleID, mode)) {
			verdict = "action_required"
			break
		}
	}
	if verdict == "no_issues_found" {
		for _, f := range report.Findings {
			if f.ConfidenceClass == model.ConfidenceDefinitive &&
				f.Severity == model.SeverityHigh &&
				(!useGating || model.IsGateEligible(f.RuleID, mode)) {
				verdict = "review_advised"
				break
			}
		}
	}
	if verdict == "no_issues_found" {
		critHeur := 0
		for _, f := range report.Findings {
			if f.ConfidenceClass == model.ConfidenceHeuristic &&
				model.SeverityWeight(f.Severity) >= model.SeverityWeight(model.SeverityCritical) {
				critHeur++
			}
		}
		if critHeur >= 3 {
			verdict = "review_advised"
		}
	}

	type riskArea struct {
		category    string
		count       int
		maxSeverity model.Severity
		confidence  model.ConfidenceClass
	}
	areaMap := make(map[string]*riskArea)
	for _, f := range report.Findings {
		cat := f.Category
		if cat == "" {
			cat = "uncategorized"
		}
		a, ok := areaMap[cat]
		if !ok {
			a = &riskArea{category: cat, confidence: f.ConfidenceClass}
			areaMap[cat] = a
		}
		a.count++
		if model.SeverityWeight(f.Severity) > model.SeverityWeight(a.maxSeverity) {
			a.maxSeverity = f.Severity
		}
		if f.ConfidenceClass == model.ConfidenceDefinitive {
			a.confidence = model.ConfidenceDefinitive
		}
	}
	areas := make([]map[string]any, 0, len(areaMap))
	for _, a := range areaMap {
		areas = append(areas, map[string]any{
			"category":     a.category,
			"count":        a.count,
			"max_severity": string(a.maxSeverity),
			"confidence":   string(a.confidence),
		})
	}

	type fileScore struct {
		path   string
		tier   int
		maxSev int
		count  int
	}
	fileMap := make(map[string]*fileScore)
	for _, f := range report.Findings {
		fs, ok := fileMap[f.File]
		if !ok {
			fs = &fileScore{path: f.File, tier: 4}
			fileMap[f.File] = fs
		}
		fs.count++
		sw := model.SeverityWeight(f.Severity)
		if sw > fs.maxSev {
			fs.maxSev = sw
		}
		upper := strings.ToUpper(f.RuleID)
		tier := 4
		if strings.HasPrefix(upper, "AGT-") {
			tier = 1
		} else if strings.HasPrefix(upper, "CI-MUTABLE-") || strings.HasPrefix(upper, "CI-PRT-") || strings.HasPrefix(upper, "CI-EXEC-") {
			tier = 2
		} else if strings.HasPrefix(upper, "DOM-TYPO-") {
			tier = 3
		}
		if tier < fs.tier {
			fs.tier = tier
		}
	}
	scores := make([]*fileScore, 0, len(fileMap))
	for _, fs := range fileMap {
		scores = append(scores, fs)
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].tier != scores[j].tier {
			return scores[i].tier < scores[j].tier
		}
		if scores[i].maxSev != scores[j].maxSev {
			return scores[i].maxSev > scores[j].maxSev
		}
		return scores[i].count > scores[j].count
	})
	reviewPriority := make([]map[string]any, 0, 10)
	for i, fs := range scores {
		if i >= 10 {
			break
		}
		priorityScore := (5-fs.tier)*10000 + fs.maxSev*100 + fs.count
		if priorityScore < 0 {
			priorityScore = 0
		}
		reasons := []string{
			fmt.Sprintf("review_tier=%d", fs.tier),
			fmt.Sprintf("max_severity_weight=%d", fs.maxSev),
			fmt.Sprintf("finding_count=%d", fs.count),
		}
		reviewPriority = append(reviewPriority, map[string]any{
			"file":    fs.path,
			"score":   priorityScore,
			"reasons": reasons,
		})
	}

	return map[string]any{
		"verdict":          verdict,
		"definitive_count": defCount,
		"heuristic_count":  heurCount,
		"correlated_count": corCount,
		"risk_score":       report.RiskScore,
		"risk_areas":       areas,
		"review_priority":  reviewPriority,
	}
}

// MCPScanRepo runs a bounded repository scan and returns a concise summary payload.
func MCPScanRepo(ctx context.Context, args map[string]any, state *MCPServerState) (map[string]any, error) {
	repoPath := strings.TrimSpace(anyToString(args["repo_path"]))
	if repoPath == "" {
		return nil, errors.New("repo_path is required")
	}
	absRepoPath, err := filepath.Abs(model.ExpandHomePath(repoPath))
	if err != nil {
		return nil, err
	}
	resolvedPath, err := filepath.EvalSymlinks(absRepoPath)
	if err != nil {
		return nil, fmt.Errorf("repo_path: %w", err)
	}
	if !PathUnderAllowedScanRoots(resolvedPath, state.AllowedScanRoots) {
		return nil, errors.New("repo_path resolves outside allowed scan roots (--mcp-allowed-roots)")
	}
	absRepoPath = resolvedPath
	info, err := os.Stat(absRepoPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("repo_path must be a directory")
	}
	requireGit := true
	if value, ok := args["require_git"]; ok {
		requireGit = anyToBool(value)
	}
	if requireGit && !isLikelyGitRepo(absRepoPath) {
		return nil, fmt.Errorf("repo_path does not appear to be a git repository: %s", absRepoPath)
	}

	scanStyle := defaultString(anyToString(args["scan_style"]), string(model.ScanStyleHybrid))
	threatMode := defaultString(anyToString(args["threat_mode"]), string(model.ThreatModeAll))
	mode := defaultString(anyToString(args["mode"]), string(model.ScanModeDeveloper))
	failOn := defaultString(anyToString(args["fail_on"]), string(model.SeverityNone))
	profile := defaultString(anyToString(args["profile"]), string(model.ProfileRepo))
	preset := anyToString(args["preset"])
	includeRules := anyToString(args["include_rules"])
	excludeRules := anyToString(args["exclude_rules"])
	baseline := anyToString(args["baseline"])

	maxFiles, err := AnyToInt(args["max_files"], DefaultMCPScanMaxFiles)
	if err != nil {
		return nil, fmt.Errorf("invalid max_files: %w", err)
	}
	maxFindings, err := AnyToInt(args["max_findings"], DefaultMCPScanMaxFindings)
	if err != nil {
		return nil, fmt.Errorf("invalid max_findings: %w", err)
	}
	sampleLimit, err := AnyToInt(args["sample_limit"], DefaultMCPSampleLimit)
	if err != nil {
		return nil, fmt.Errorf("invalid sample_limit: %w", err)
	}
	if sampleLimit < 0 {
		sampleLimit = 0
	}
	if sampleLimit > 200 {
		sampleLimit = 200
	}
	workers, err := AnyToInt(args["workers"], 0)
	if err != nil {
		return nil, fmt.Errorf("invalid workers: %w", err)
	}

	runArgs := []string{
		"--path", absRepoPath,
		"--profile", profile,
		"--scan-style", scanStyle,
		"--threat-mode", threatMode,
		"--mode", mode,
		"--policy-checks=true",
		"--format", "json",
		"--fail-on", failOn,
		"--max-files", fmt.Sprintf("%d", maxFiles),
		"--max-findings", fmt.Sprintf("%d", maxFindings),
		// Always disable host IDE MCP discovery: we scan the target repo's files
		// through the pattern engine, which already finds .cursor/mcp.json etc.
		// The auto-discover enrichment probes the host IDE's global config paths
		// (~/.cursor/mcp.json) and would pollute findings with the operator's own
		// environment rather than the target repo under review.
		"--auto-discover-mcp=false",
	}
	if preset != "" {
		runArgs = append(runArgs, "--preset", preset)
	}
	if includeRules != "" {
		runArgs = append(runArgs, "--include-rules", includeRules)
	}
	if excludeRules != "" {
		runArgs = append(runArgs, "--exclude-rules", excludeRules)
	}
	if workers > 0 {
		runArgs = append(runArgs, "--workers", fmt.Sprintf("%d", workers))
	}
	if anyToBool(args["incremental"]) {
		runArgs = append(runArgs, "--incremental")
	}
	if baseline != "" {
		runArgs = append(runArgs, "--baseline", baseline)
	}
	if anyToBool(args["diff_only"]) {
		runArgs = append(runArgs, "--diff-only")
	}

	var outBuf, errBuf bytes.Buffer
	exitCode := state.RunScan(ctx, runArgs, &outBuf, &errBuf)
	if exitCode != 0 && exitCode != 3 {
		return nil, fmt.Errorf("scan failed with exit code %d: %s", exitCode, strings.TrimSpace(errBuf.String()))
	}

	var report model.Report
	if err := json.Unmarshal(outBuf.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("failed parsing scan report: %w", err)
	}

	samples := make([]map[string]any, 0, min(sampleLimit, len(report.Findings)))
	for _, finding := range report.Findings[:min(sampleLimit, len(report.Findings))] {
		samples = append(samples, map[string]any{
			"rule_id":          finding.RuleID,
			"severity":         finding.Severity,
			"confidence_class": string(finding.ConfidenceClass),
			"file":             finding.File,
			"line":             finding.Line,
			"title":            finding.Title,
			"category":         finding.Category,
			"mitre":            finding.Mitre,
			"match":            finding.Match,
			"baseline":         finding.BaselineState,
			"full_path":        absRepoPath,
		})
	}

	return map[string]any{
		"repo_path":          absRepoPath,
		"exit_code":          exitCode,
		"mode":               mode,
		"risk_score":         report.RiskScore,
		"threshold_exceeded": report.ThresholdExceeded,
		"ruleset_hash":       report.RulesetHash,
		"scan_style":         report.ScanStyle,
		"threat_mode":        report.ThreatMode,
		"policy_checks":      report.PolicyChecks,
		"scanned_files":      report.ScannedFiles,
		"skipped_files":      report.SkippedFiles,
		"permission_errors":  report.PermissionErrors,
		"findings_total":     len(report.Findings),
		"findings_by_severity": map[string]any{
			"critical": report.FindingsBySeverity[string(model.SeverityCritical)],
			"high":     report.FindingsBySeverity[string(model.SeverityHigh)],
			"medium":   report.FindingsBySeverity[string(model.SeverityMedium)],
			"low":      report.FindingsBySeverity[string(model.SeverityLow)],
			"info":     report.FindingsBySeverity[string(model.SeverityInfo)],
		},
		"trust_assessment": BuildTrustAssessment(report),
		"findings_by_confidence": map[string]any{
			"definitive": report.FindingsByConfidence[string(model.ConfidenceDefinitive)],
			"heuristic":  report.FindingsByConfidence[string(model.ConfidenceHeuristic)],
			"correlated": report.FindingsByConfidence[string(model.ConfidenceCorrelated)],
		},
		"sample_findings":       samples,
		"sample_findings_count": len(samples),
		"sample_findings_note":  sampleNote(len(report.Findings), sampleLimit),
		"stderr":                strings.TrimSpace(errBuf.String()),
	}, nil
}

func sampleNote(total, limit int) string {
	if total <= limit {
		return fmt.Sprintf("all %d findings shown", total)
	}
	return fmt.Sprintf("showing %d of %d total findings; use skeptic_daemon_report for full results or increase sample_limit", limit, total)
}

func isLikelyGitRepo(path string) bool {
	gitPath := filepath.Join(path, ".git")
	info, err := os.Stat(gitPath)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return true
	}
	return info.Mode().IsRegular()
}

// HandleMCPResourcesList returns available MCP resources.
func HandleMCPResourcesList() map[string]any {
	return map[string]any{
		"resources": []map[string]any{
			{
				"uri":         "skeptic://rules/builtin",
				"name":        "Built-in rules",
				"description": "List of all built-in rule IDs and descriptions.",
				"mimeType":    "application/json",
			},
			{
				"uri":         "skeptic://rules/external",
				"name":        "External rules",
				"description": "External rule metadata (CLI-configured).",
				"mimeType":    "application/json",
			},
			{
				"uri":         "skeptic://report/latest",
				"name":        "Latest report",
				"description": "Most recent scan report summary.",
				"mimeType":    "application/json",
			},
			{
				"uri":         "skeptic://config/active",
				"name":        "Active configuration",
				"description": "Server configuration: enabled tools, scan roots, cooldown, presets, operating modes.",
				"mimeType":    "application/json",
			},
		},
	}
}

// HandleMCPResourcesRead returns content for a specific resource URI.
func HandleMCPResourcesRead(params json.RawMessage, state *MCPServerState) (map[string]any, error) {
	var readParams struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(params, &readParams); err != nil {
		return nil, fmt.Errorf("invalid resources/read params: %w", err)
	}
	switch readParams.URI {
	case "skeptic://rules/builtin":
		rules := state.DefaultRules()
		summaries := make([]map[string]string, 0, len(rules))
		for _, r := range rules {
			summaries = append(summaries, map[string]string{
				"id":       r.ID,
				"title":    r.Title,
				"severity": string(r.Severity),
				"category": r.Category,
			})
		}
		text, err := json.MarshalIndent(summaries, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal rules summary: %w", err)
		}
		return map[string]any{
			"contents": []map[string]any{
				{"uri": readParams.URI, "mimeType": "application/json", "text": string(text)},
			},
		}, nil
	case "skeptic://rules/external":
		extText := `{"status":"external_rules_loaded_via_cli"}`
		return map[string]any{
			"contents": []map[string]any{
				{"uri": readParams.URI, "mimeType": "application/json", "text": extText},
			},
		}, nil
	case "skeptic://report/latest":
		// This resource serves the durable on-disk report written by the daemon
		// after each scan, so it survives daemon restarts. It always returns a
		// summary (top 100 medium+ findings) suitable for LLM context windows.
		// Use the skeptic_daemon_report tool for live in-memory access with custom filters.
		text := latestReportResource(state)
		return map[string]any{
			"contents": []map[string]any{
				{"uri": readParams.URI, "mimeType": "application/json", "text": text},
			},
		}, nil
	case "skeptic://config/active":
		configData := map[string]any{
			"allow_trigger":           state.AllowTrigger,
			"allow_ingest":            state.AllowIngest,
			"require_ingest_approval": state.RequireIngestApproval,
			"trigger_cooldown":        state.TriggerCooldown.String(),
			"allowed_scan_roots":      state.AllowedScanRoots,
			"ingest_allowed_hosts":    state.IngestAllowedHosts,
			"rules_out_dir":           state.RulesOutDir,
			"audit_log_path":          state.AuditLogPath,
			"builtin_rule_count":      len(state.DefaultRules()),
			"daemon_connected":        state.DaemonClient != nil,
		}
		if state.DaemonClient != nil {
			configData["daemon_url"] = state.DaemonClient.BaseURL
		}
		text, err := json.MarshalIndent(configData, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshal config: %w", err)
		}
		return map[string]any{
			"contents": []map[string]any{
				{"uri": readParams.URI, "mimeType": "application/json", "text": string(text)},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown resource URI: %s", readParams.URI)
	}
}

func mcpToolSuccess(payload map[string]any) map[string]any {
	text, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		text = []byte("{}")
	}
	hash := sha256.Sum256(text)
	return map[string]any{
		"content": []map[string]any{
			{
				"type": "text",
				"text": string(text),
			},
		},
		"structuredContent": payload,
		"isError":           false,
		"integrity_sha256":  hex.EncodeToString(hash[:]),
	}
}

func handleWaive(args map[string]any, state *MCPServerState) (map[string]any, error) {
	repoPath, _ := args["repo_path"].(string) //nolint:errcheck // zero value "" is handled below
	file, _ := args["file"].(string)          //nolint:errcheck // zero value "" is handled below
	rule, _ := args["rule"].(string)          //nolint:errcheck // zero value "" is handled below
	reason, _ := args["reason"].(string)      //nolint:errcheck // zero value "" is handled below

	if repoPath == "" {
		return nil, errors.New("repo_path is required")
	}
	if reason == "" {
		return nil, errors.New("reason is required")
	}
	if file == "" && rule == "" {
		return nil, errors.New("at least one of file or rule is required")
	}

	scanFn := func(path string) (*model.Report, error) {
		scanArgs := []string{
			"--path", path,
			"--format", "json",
			"--fail-on", "none",
			"--quiet",
		}
		var outBuf, errBuf bytes.Buffer
		exitCode := state.RunScan(context.Background(), scanArgs, &outBuf, &errBuf)
		if exitCode != 0 && exitCode != 3 {
			return nil, fmt.Errorf("scan failed with exit code %d: %s", exitCode, strings.TrimSpace(errBuf.String()))
		}
		var report model.Report
		if err := json.Unmarshal(outBuf.Bytes(), &report); err != nil {
			return nil, fmt.Errorf("parse scan output: %w", err)
		}
		return &report, nil
	}

	result, err := suppress.RunWaive(suppress.WaiveOptions{
		RepoPath: repoPath,
		File:     file,
		RuleID:   rule,
		Reason:   reason,
	}, scanFn)
	if err != nil {
		return nil, fmt.Errorf("waive: %w", err)
	}

	payload := map[string]any{
		"total_findings":   result.TotalFindings,
		"matched_findings": result.MatchedFindings,
		"waivers_created":  result.WaiversCreated,
		"waiver_path":      result.WaiverPath,
		"active_after":     result.ActiveAfter,
		"suppressed_after": result.SuppressedAfter,
		"waived_rule_ids":  result.WaivedRuleIDs,
	}
	if result.FileSHA256 != "" {
		payload["file_sha256"] = result.FileSHA256
	}
	return applyMCPToolNonce(mcpToolSuccess(payload), args), nil
}

// applyMCPToolNonce echoes _nonce from tools/call arguments into the JSON-RPC result map when present.
func applyMCPToolNonce(result map[string]any, arguments map[string]any) map[string]any {
	if arguments == nil {
		return result
	}
	if v, ok := arguments["_nonce"]; ok {
		result["_nonce"] = v
	}
	return result
}

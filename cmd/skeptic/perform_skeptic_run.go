package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	configpkg "github.com/TGPSKI/skeptic/internal/config"
	enrichpkg "github.com/TGPSKI/skeptic/internal/enrich"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
	reportpkg "github.com/TGPSKI/skeptic/internal/report"
	"github.com/TGPSKI/skeptic/internal/rules"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
	"github.com/TGPSKI/skeptic/internal/suppress"
)

type skepticRunMode struct {
	ExternalLogger *logging.Logger
	SkipStdout     bool
}

func registerRunFlags(fs *flag.FlagSet, raw *runRawOptions, stderr io.Writer) {
	fs.SetOutput(stderr)
	fs.StringVar(&raw.TargetPath, "path", ".", "file or directory to scan")
	fs.StringVar(&raw.TargetPath, "p", ".", "file or directory to scan")
	fs.StringVar(&raw.PathsRaw, "paths", "", "comma-separated scan paths (overrides --path)")
	fs.StringVar(&raw.ProfileRaw, "profile", string(model.ProfileRepo), "scan profile: repo|developer|container|fullfs")
	fs.StringVar(&raw.ScanStyleRaw, "scan-style", string(model.ScanStylePattern), "scan style: pattern|behavior|hybrid")
	fs.StringVar(&raw.ThreatModeRaw, "threat-mode", string(model.ThreatModeAll), "threat focus: all|machine-identity|ai-workload")
	fs.BoolVar(&raw.PolicyChecks, "policy-checks", true, "enable workflow trust, token scope, and dependency checks")
	fs.BoolVar(&raw.AutoDiscoverMCP, "auto-discover-mcp", false, "scan local MCP client configs for risky patterns")
	fs.StringVar(&raw.RulesFileRaw, "rules-file", "", "comma-separated external rule JSON files")
	fs.StringVar(&raw.RulesDir, "rules-dir", "", "directory of external rule JSON files")
	fs.BoolVar(&raw.NoRulepacks, "no-rulepacks", false, "skip auto-loading rulepacks/campaigns/")
	fs.StringVar(&raw.RulesSHA256Raw, "rules-sha256", "", "comma-separated SHA256 for --rules-file integrity")
	fs.StringVar(&raw.RulesPubKeyRaw, "rules-pubkey", "", "Ed25519 public key PEM paths for rule verification (comma-sep)")
	fs.BoolVar(&raw.RequireSignedRules, "require-signed-rules", false, "require detached .sig for external rule packs")
	fs.BoolVar(&raw.NoDefaultRules, "no-default-rules", false, "disable built-in rules; external only")
	fs.StringVar(&raw.IncludeRulesRaw, "include-rules", "", "only evaluate matching rule IDs (comma-sep, glob)")
	fs.StringVar(&raw.ExcludeRulesRaw, "exclude-rules", "", "skip matching rule IDs (comma-sep, glob)")
	fs.StringVar(&raw.IgnorePathsRaw, "ignore-paths", "", "skip paths matching globs (comma-sep)")
	fs.StringVar(&raw.WaiversRaw, "waivers", "", "waiver JSON file path (empty = no suppression)")
	fs.StringVar(&raw.OutputFormatRaw, "format", string(model.FormatText), "output format: text|json|sarif|markdown")
	fs.StringVar(&raw.OutputFormatRaw, "f", string(model.FormatText), "output format: text|json|sarif|markdown")
	fs.StringVar(&raw.OutPath, "out", "", "write the report to a file (empty = stdout)")
	fs.StringVar(&raw.OutPath, "o", "", "write the report to a file (empty = stdout)")
	fs.StringVar(&raw.RuleQualityRaw, "rule-quality", string(model.RuleQualityWarn), "rule quality mode: off|warn|strict")
	fs.StringVar(&raw.FailOnRaw, "fail-on", string(model.SeverityCritical), "fail threshold: none|info|low|medium|high|critical")
	fs.IntVar(&raw.FailOnScore, "fail-on-score", 0, "fail if risk score >= N (0 disables)")
	fs.StringVar(&raw.ToolName, "tool-name", "", "tool context for FP reduction (e.g. Bash, Edit)")
	fs.Int64Var(&raw.MaxBytes, "max-bytes", scanpkg.DefaultMaxBytes, "skip files larger than N bytes")
	fs.BoolVar(&raw.IgnorePermissionErrors, "ignore-permission-errors", true, "skip permission-denied during recursive scan")
	fs.IntVar(&raw.MaxFiles, "max-files", 0, "max files to scan (0 = unlimited)")
	fs.IntVar(&raw.Workers, "workers", 0, "parallel scan goroutines (0 = NumCPU)")
	fs.IntVar(&raw.MaxFindings, "max-findings", 20000, "max total findings to report")
	fs.IntVar(&raw.MaxFindingsPerFile, "max-findings-per-file", 2000, "max findings per file")
	fs.BoolVar(&raw.RedactSecrets, "redact-secrets", true, "redact secrets in finding snippets")
	fs.BoolVar(&raw.Incremental, "incremental", false, "only scan files changed since last run")
	fs.StringVar(&raw.StateCachePath, "state-cache", ".skeptic-state.json", "incremental cache state path")
	fs.StringVar(&raw.BaselinePath, "baseline", "", "prior JSON report path for diff comparison (empty = disabled)")
	fs.BoolVar(&raw.DiffOnly, "diff-only", false, "emit only new findings (requires --baseline)")
	fs.StringVar(&raw.WriteBaselinePath, "write-baseline", "", "save report JSON for future baselines (empty = disabled)")
	fs.IntVar(&raw.Verbosity, "verbose", 0, "verbosity: 0=warn, 1=info, 2=debug, 3=perf")
	fs.BoolVar(&raw.Quiet, "quiet", false, "suppress non-error output")
	fs.StringVar(&raw.LogFilePath, "log-file", "", "write logs to file (empty = stderr only)")
	fs.StringVar(&raw.ConfigPath, "config", "", "path to config file (empty = auto-discover .skeptic.*)")
	fs.StringVar(&raw.ModeRaw, "mode", string(model.ScanModeDeveloper), "operating mode: developer|ir|deep")
	fs.StringVar(&raw.PresetRaw, "preset", "", "scan preset: quick|dev|ci|hunt|machine-identity|ai-workload")
	fs.StringVar(&raw.BehaviorBaselinePath, "behavior-baseline", "", "behavior profile baseline path (enables drift)")
	fs.StringVar(&raw.BehaviorHistoryPath, "behavior-history", "", "behavior profile history JSON (enables trends)")
	fs.Float64Var(&raw.DriftSeverityMultiplier, "drift-severity-multiplier", 2.0, "drift severity scaling factor (e.g. 2.0 = double)")
	fs.StringVar(&raw.DriftAllowedChainsRaw, "drift-allowed-chains", "", "path globs of new chains to ignore for drift (comma-sep)")
	fs.BoolVar(&raw.GitCorrelation, "git-correlation", false, "correlate findings by git author/time window")
	fs.StringVar(&raw.ProvenanceManifestPath, "provenance-manifest", "", "provenance manifest for hash verification")
	fs.BoolVar(&raw.RequireSignedProvenanceManifest, "require-signed-manifest", false, "require Ed25519 signature on provenance manifest")
	fs.StringVar(&raw.SBOMPath, "sbom", "", "CycloneDX/SPDX JSON SBOM for cross-reference")
	fs.IntVar(&raw.IdentityGraphHops, "identity-graph-hops", 3, "max RBAC graph hops for wildcard reachability")
	fs.BoolVar(&raw.AhoCorasick, "aho-corasick", false, "Aho-Corasick pre-filter instead of strings.Contains")
	fs.BoolVar(&raw.NFKC, "nfkc", true, "NFKC unicode normalization before matching")
	fs.BoolVar(&raw.XORBrute, "xor-brute", false, "single-byte XOR brute-force on high-entropy content")
	fs.IntVar(&raw.MaxDecodeDepth, "max-decode-depth", 3, "max recursive payload decode depth")
	fs.Usage = func() { writeTopLevelUsage(fs, stderr) }
}

func validateRunFlags(raw *runRawOptions, stderr io.Writer) error {
	if raw.MaxBytes <= 0 {
		return fmt.Errorf("max-bytes must be > 0")
	}
	if raw.MaxFiles < 0 {
		return fmt.Errorf("max-files must be >= 0")
	}
	if raw.Workers < 0 {
		return fmt.Errorf("workers must be >= 0")
	}
	if raw.MaxFindings <= 0 {
		return fmt.Errorf("max-findings must be > 0")
	}
	if raw.MaxFindingsPerFile <= 0 {
		return fmt.Errorf("max-findings-per-file must be > 0")
	}
	if raw.IdentityGraphHops < 0 {
		return fmt.Errorf("identity-graph-hops must be >= 0 (0 uses built-in default)")
	}
	if raw.DiffOnly && strings.TrimSpace(raw.BaselinePath) == "" {
		return fmt.Errorf("--diff-only requires --baseline")
	}
	if raw.RequireSignedRules && strings.TrimSpace(raw.RulesFileRaw) == "" && strings.TrimSpace(raw.RulesDir) == "" {
		return fmt.Errorf("--require-signed-rules requires external rule files via --rules-file or --rules-dir")
	}
	return nil
}

// filterFindingsByRulePatterns applies --include-rules / --exclude-rules to the aggregated
// finding list so policy, behavior, and correlation findings respect the same ID patterns as
// built-in and external pattern rules.
func filterFindingsByRulePatterns(findings []model.Finding, include, exclude []string) []model.Finding {
	if len(include) == 0 && len(exclude) == 0 {
		return findings
	}
	out := make([]model.Finding, 0, len(findings))
	for _, f := range findings {
		if len(include) > 0 {
			ok := false
			for _, p := range include {
				if rules.RuleIDMatchesPattern(f.RuleID, p) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		excluded := false
		for _, p := range exclude {
			if rules.RuleIDMatchesPattern(f.RuleID, p) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		out = append(out, f)
	}
	return out
}

func enrichReportFindings(report *model.Report, raw *runRawOptions, roots []string, threatMode model.ThreatMode, logger *logging.Logger) {
	enrichpkg.EnrichReport(report, enrichpkg.Options{
		PolicyChecks:                    raw.PolicyChecks,
		IdentityGraphHops:               raw.IdentityGraphHops,
		RedactSecrets:                   raw.RedactSecrets,
		ProvenanceManifestPath:          raw.ProvenanceManifestPath,
		RequireSignedProvenanceManifest: raw.RequireSignedProvenanceManifest,
		SBOMPath:                        raw.SBOMPath,
		AutoDiscoverMCP:                 raw.AutoDiscoverMCP,
		BehaviorBaselinePath:            raw.BehaviorBaselinePath,
		DriftSeverityMultiplier:         raw.DriftSeverityMultiplier,
		DriftAllowedChainsRaw:           raw.DriftAllowedChainsRaw,
		BehaviorHistoryPath:             raw.BehaviorHistoryPath,
		GitCorrelation:                  raw.GitCorrelation,
	}, roots, threatMode, logger)
}

// resolvedRunConfig holds values produced by resolveRunConfig for the scan and post-scan phases.
type resolvedRunConfig struct {
	logger         *logging.Logger
	logCloser      io.Closer
	failOn         model.Severity
	outputFormat   model.OutputFormat
	outPath        string
	roots          []string
	loadedRules    []model.Rule
	includeRuleIDs []string
	excludeRuleIDs []string
	ignorePaths    []string
	rulesetHash    string
	scanStyle      model.ScanStyle
	threatMode     model.ThreatMode
	scanMode       model.ScanMode
	profile        model.ScanProfile
	perfFileLog    bool
}

func resolveRunConfig(fs *flag.FlagSet, raw *runRawOptions, stderr io.Writer, perfFileLog bool, mode skepticRunMode) (resolvedRunConfig, int) {
	var out resolvedRunConfig
	out.perfFileLog = perfFileLog

	resolved, err := configpkg.ResolveConfigLayers(fs, raw)
	if err != nil {
		fmt.Fprintf(stderr, "config resolution failed: %v\n", err)
		return resolvedRunConfig{}, 2
	}
	out.scanMode = resolved.ScanMode
	if err := validateRunFlags(raw, stderr); err != nil {
		fmt.Fprintln(stderr, err)
		return resolvedRunConfig{}, 2
	}

	if mode.ExternalLogger != nil {
		out.logger = mode.ExternalLogger
	} else {
		var logErr error
		out.logger, out.logCloser, logErr = logging.SetupLogger(stderr, raw.LogFilePath, raw.Quiet, raw.Verbosity)
		if logErr != nil {
			fmt.Fprintf(stderr, "failed to initialize logger: %v\n", logErr)
			return resolvedRunConfig{}, 1
		}
	}
	if resolved.ConfigPath != "" {
		out.logger.Infof("loaded config file: %s", resolved.ConfigPath)
	}
	out.logger.Infof("applied mode: %s", resolved.ScanMode)
	if resolved.Preset != "" {
		out.logger.Infof("applied preset: %s", resolved.Preset)
	}

	failOn, err := model.ParseSeverity(raw.FailOnRaw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --fail-on value: %v\n", err)
		return resolvedRunConfig{}, 2
	}
	out.failOn = failOn
	outputFormat, err := parseOutputFormat(raw.OutputFormatRaw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --format value: %v\n", err)
		return resolvedRunConfig{}, 2
	}
	out.outputFormat = outputFormat
	out.outPath = raw.OutPath
	ruleQualityMode, err := rules.ParseRuleQualityMode(raw.RuleQualityRaw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --rule-quality value: %v\n", err)
		return resolvedRunConfig{}, 2
	}
	profile, err := model.ParseProfile(raw.ProfileRaw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --profile value: %v\n", err)
		return resolvedRunConfig{}, 2
	}
	out.profile = profile
	scanStyle, err := model.ParseScanStyle(raw.ScanStyleRaw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --scan-style value: %v\n", err)
		return resolvedRunConfig{}, 2
	}
	out.scanStyle = scanStyle
	threatMode, err := model.ParseThreatMode(raw.ThreatModeRaw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --threat-mode value: %v\n", err)
		return resolvedRunConfig{}, 2
	}
	out.threatMode = threatMode
	roots, err := resolveScanRoots(raw.TargetPath, raw.PathsRaw, profile)
	if err != nil {
		fmt.Fprintf(stderr, "invalid scan roots: %v\n", err)
		return resolvedRunConfig{}, 2
	}
	out.roots = roots
	rulesDir := raw.RulesDir
	if rulesDir == "" && !raw.NoRulepacks {
		sys, _, _ := configpkg.LoadSystemConfig("")
		if !sys.CorpusNoRulepacks {
			if info, statErr := os.Stat("rulepacks/campaigns"); statErr == nil && info.IsDir() {
				rulesDir = "rulepacks/campaigns"
				if out.logger != nil {
					out.logger.Infof("auto-discovered rulepacks at %s", rulesDir)
				}
			}
		}
	}
	loadedRules, err := rules.BuildRuleSet(
		!raw.NoDefaultRules, rules.DefaultRules(), raw.RulesFileRaw, rulesDir,
		raw.RulesSHA256Raw, raw.RulesPubKeyRaw, raw.RequireSignedRules, ruleQualityMode, out.logger,
	)
	if err != nil {
		fmt.Fprintf(stderr, "failed to build ruleset: %v\n", err)
		return resolvedRunConfig{}, 1
	}
	includeRuleIDs := rules.SplitCSV(raw.IncludeRulesRaw)
	excludeRuleIDs := rules.SplitCSV(raw.ExcludeRulesRaw)
	loadedRules = rules.FilterRules(loadedRules, includeRuleIDs, excludeRuleIDs)
	out.loadedRules = loadedRules
	out.includeRuleIDs = includeRuleIDs
	out.excludeRuleIDs = excludeRuleIDs
	hasExternalRules := strings.TrimSpace(raw.RulesFileRaw) != "" || strings.TrimSpace(raw.RulesDir) != ""
	if len(loadedRules) == 0 {
		if raw.NoDefaultRules && !hasExternalRules {
			fmt.Fprintln(stderr, "ruleset is empty: enable default rules or provide external rules")
			return resolvedRunConfig{}, 2
		}
		// Allow zero pattern rules when defaults were narrowed away by --include-rules or
		// external rules were fully filtered; policy and other checks may still emit findings.
	}
	if raw.Workers == 0 {
		raw.Workers = max(2, runtime.GOMAXPROCS(0)*2)
	}
	rulesetHash := scanpkg.ComputeRulesetHash(loadedRules)
	out.rulesetHash = rulesetHash
	out.logger.Infof(
		"scan start profile=%s mode=%s roots=%d rules=%d workers=%d max_files=%d max_findings=%d incremental=%t style=%s threat_mode=%s policy_checks=%t",
		profile, out.scanMode, len(roots), len(loadedRules), raw.Workers, raw.MaxFiles, raw.MaxFindings, raw.Incremental, scanStyle, threatMode, raw.PolicyChecks,
	)

	ignorePaths := rules.SplitCSV(raw.IgnorePathsRaw)
	out.ignorePaths = ignorePaths
	if prefixes := scanpkg.ExemptedRulePrefixes(raw.ToolName); len(prefixes) > 0 {
		out.excludeRuleIDs = append(out.excludeRuleIDs, prefixes...)
		out.logger.Infof("tool-name=%s: excluding rule prefixes %v", raw.ToolName, prefixes)
	}

	return out, 0
}

// gateSuppressedRuleIDCap bounds how many rule IDs the warning names.
const gateSuppressedRuleIDCap = 5

// warnGateSuppressed reports findings that met the --fail-on severity but were
// excluded from gating by rule-family eligibility. Without this, a run that
// found qualifying issues and still exited 0 looks identical to a clean run.
func warnGateSuppressed(report *model.Report, cfg resolvedRunConfig) {
	ids := model.GateSuppressedRuleIDs(report.Findings, cfg.failOn, cfg.scanMode)
	if len(ids) == 0 {
		return
	}
	shown := ids
	suffix := ""
	if len(shown) > gateSuppressedRuleIDCap {
		shown = shown[:gateSuppressedRuleIDCap]
		suffix = fmt.Sprintf(", +%d more", len(ids)-gateSuppressedRuleIDCap)
	}
	cfg.logger.Warnf(
		"reached --fail-on %s but advisory in %s mode, did not gate: %s%s",
		cfg.failOn, cfg.scanMode, strings.Join(shown, ", "), suffix,
	)
}

func postProcessReport(report *model.Report, raw *runRawOptions, cfg resolvedRunConfig, stdout, stderr io.Writer, mode skepticRunMode) int {
	enrichReportFindings(report, raw, cfg.roots, cfg.threatMode, cfg.logger)

	report.Findings = filterFindingsByRulePatterns(report.Findings, cfg.includeRuleIDs, cfg.excludeRuleIDs)
	scanpkg.SortFindings(report.Findings)
	report.FindingsBySeverity = scanpkg.SummarizeFindings(report.Findings)
	if cfg.failOn != model.SeverityNone {
		report.ThresholdExceeded = scanpkg.ThresholdExceeded(report.Findings, cfg.failOn, cfg.scanMode)
	}

	if wpath := strings.TrimSpace(raw.WaiversRaw); wpath != "" {
		wf, werr := suppress.LoadWaiverFile(model.ExpandHomePath(wpath))
		if werr != nil {
			fmt.Fprintf(stderr, "failed to load waivers: %v\n", werr)
			return 1
		}
		fileHashes := suppress.ComputeFileHashes(report.Findings)
		report.Findings = suppress.ApplyWaivers(report.Findings, wf.Waivers, fileHashes)
		report.FindingsBySeverity = scanpkg.SummarizeFindings(report.Findings)
		report.RiskScore = scanpkg.ComputeRiskScore(report.Findings)
		if cfg.failOn != model.SeverityNone {
			report.ThresholdExceeded = scanpkg.ThresholdExceeded(report.Findings, cfg.failOn, cfg.scanMode)
		}
	}

	if strings.TrimSpace(raw.BaselinePath) != "" {
		baselineReport, err := reportpkg.LoadBaselineReport(raw.BaselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "failed to load baseline report: %v\n", err)
			return 1
		}
		report.BaselinePath = raw.BaselinePath
		reportpkg.ApplyBaselineDiff(report, baselineReport, raw.DiffOnly)
		if raw.DiffOnly && cfg.failOn != model.SeverityNone {
			report.ThresholdExceeded = scanpkg.ThresholdExceeded(report.Findings, cfg.failOn, cfg.scanMode)
		}
	}

	if !mode.SkipStdout {
		if cfg.outputFormat == model.FormatSARIF {
			report.ToolVersion = skepticToolVersion()
		}
		if _, code := emitReport(stdout, stderr, *report, cfg.outputFormat, cfg.outPath); code != 0 {
			return code
		}
	}
	if strings.TrimSpace(raw.WriteBaselinePath) != "" {
		if err := reportpkg.WriteJSONReport(raw.WriteBaselinePath, *report); err != nil {
			fmt.Fprintf(stderr, "failed to write baseline report: %v\n", err)
			return 1
		}
	}
	cfg.logger.Infof(
		"scan finished scanned=%d skipped=%d cache_skipped=%d findings=%d threshold_exceeded=%t",
		report.ScannedFiles, report.SkippedFiles, report.CacheSkippedFiles, len(report.Findings), report.ThresholdExceeded,
	)
	if report.ThresholdExceeded {
		return 3
	}
	warnGateSuppressed(report, cfg)
	if raw.FailOnScore > 0 && report.RiskScore >= raw.FailOnScore {
		report.ThresholdExceeded = true
		return 3
	}
	return 0
}

func performSkepticRun(args []string, stdout, stderr io.Writer, scan func(context.Context, []model.Rule, model.ScanOptions) (model.Report, error), mode skepticRunMode) (model.Report, int) {
	raw := runRawOptions{}
	prof := profileOptions{}
	fs := flag.NewFlagSet("skeptic", flag.ContinueOnError)
	registerRunFlags(fs, &raw, stderr)
	registerProfileFlags(fs, &prof)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return model.Report{}, 0
		}
		return model.Report{}, 2
	}

	if positional := fs.Args(); len(positional) > 0 {
		visited := configpkg.VisitedFlagNames(fs)
		if !configpkg.FlagWasSet(visited, "path") && !configpkg.FlagWasSet(visited, "p") && strings.TrimSpace(raw.PathsRaw) == "" {
			raw.TargetPath = positional[0]
			if len(positional) > 1 {
				raw.PathsRaw = strings.Join(positional, ",")
			}
		} else {
			fmt.Fprintf(stderr, "unexpected positional arguments: %v (use --path or positional args, not both)\n", positional)
			return model.Report{}, 2
		}
	}

	if prof.PerfDebug {
		applyPerfDebugDefaults(&prof)
		if raw.Verbosity < 2 {
			raw.Verbosity = 2
		}
	}
	perfFileLog := raw.Verbosity >= 3 || prof.PerfDebug

	stopProfile, profErr := startProfiling(prof, stderr)
	if profErr != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", profErr)
		return model.Report{}, 1
	}
	defer stopProfile()

	cfg, resolveCode := resolveRunConfig(fs, &raw, stderr, perfFileLog, mode)
	if resolveCode != 0 {
		return model.Report{}, resolveCode
	}
	if cfg.logCloser != nil {
		defer func() {
			if cerr := cfg.logCloser.Close(); cerr != nil {
				fmt.Fprintf(stderr, "warning: close log file: %v\n", cerr)
			}
		}()
	}

	report, err := scan(context.Background(), cfg.loadedRules, model.ScanOptions{
		Paths: cfg.roots, Profile: cfg.profile, ScanStyle: cfg.scanStyle, ThreatMode: cfg.threatMode, Mode: cfg.scanMode,
		PolicyChecks: raw.PolicyChecks, MaxBytes: raw.MaxBytes, FailOn: cfg.failOn,
		IgnorePermissionErrors: raw.IgnorePermissionErrors, MaxFiles: raw.MaxFiles, Workers: raw.Workers,
		MaxFindings: raw.MaxFindings, MaxFindingsPerFile: raw.MaxFindingsPerFile, RedactSecrets: raw.RedactSecrets,
		Incremental: raw.Incremental, StateCachePath: raw.StateCachePath, RulesetHash: cfg.rulesetHash, Logger: cfg.logger,
		ProgressLog: raw.Verbosity >= 2, PerfFileLog: cfg.perfFileLog,
		IncludeRules: cfg.includeRuleIDs, ExcludeRules: cfg.excludeRuleIDs, IgnorePaths: cfg.ignorePaths,
		AhoCorasick: raw.AhoCorasick, NFKC: raw.NFKC, ToolName: raw.ToolName,
		XORBrute: raw.XORBrute, MaxDecodeDepth: raw.MaxDecodeDepth,
	})
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return model.Report{}, 1
	}

	postCode := postProcessReport(&report, &raw, cfg, stdout, stderr, mode)
	if postCode == 3 {
		return report, 3
	}
	if postCode != 0 {
		return model.Report{}, postCode
	}
	return report, 0
}

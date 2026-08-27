package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/correlation"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// Scan engine constants for file size limits and performance thresholds.
const (
	DefaultMaxBytes = 2 * 1024 * 1024
	maxLineBytes    = 2 * 1024 * 1024
	// eBPF stack frames are limited (commonly 512 bytes); very long paths
	// can evade naive runtime instrumentation.
	ebpfPathVisibilityLimit = 512
	slowFileThreshold       = 1 * time.Second
	// Lines longer than this are likely minified code or serialized data blobs
	// where per-line regex matching has pathological cost and near-zero signal.
	maxRegexLineLen = 32 * 1024
	// Files with more lines than this are scanned as raw content only (no
	// per-line iteration). Prevents OOM on minified single-line megafiles
	// that split into millions of trivial segments.
	maxScanLines = 500_000
)

var errMaxFilesReached = errors.New("max files reached")

type scanTask struct {
	path            string
	root            string
	useAbsolutePath bool
}

type scanResult struct {
	path             string
	findings         []model.Finding
	scanned          int
	skipped          int
	permissionErrors int
	duration         time.Duration
	err              error
}

// normalizeOptions applies default values for zero-value ScanOptions fields.
func normalizeOptions(opts *model.ScanOptions, rules []model.Rule) {
	if opts.Workers <= 0 {
		opts.Workers = max(2, runtime.GOMAXPROCS(0)*2)
	}
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = 20000
	}
	if opts.MaxFindingsPerFile <= 0 {
		opts.MaxFindingsPerFile = 2000
	}
	if opts.ScanStyle == "" {
		opts.ScanStyle = model.ScanStylePattern
	}
	if opts.ThreatMode == "" {
		opts.ThreatMode = model.ThreatModeAll
	}
	if opts.Logger == nil {
		opts.Logger = logging.NewLogger(logging.LogError, io.Discard)
	}
	if strings.TrimSpace(opts.StateCachePath) == "" {
		opts.StateCachePath = ".skeptic-state.json"
	}
	if strings.TrimSpace(opts.RulesetHash) == "" {
		opts.RulesetHash = ComputeRulesetHash(rules)
	}
	if opts.MaxDecodeDepth <= 0 {
		opts.MaxDecodeDepth = 3
	}
}

// resolveConfidenceClass returns the rule's override or the default for its ID prefix.
func resolveConfidenceClass(rule model.Rule) model.ConfidenceClass {
	if rule.ConfidenceClass != "" {
		return rule.ConfidenceClass
	}
	return model.DefaultConfidenceForRuleID(rule.ID)
}

// initScanState builds the initial report and incremental state cache for a scan run.
func initScanState(opts model.ScanOptions) (model.Report, *IncrementalStateCache, error) {
	report := model.Report{
		TargetPaths:     opts.Paths,
		Profile:         opts.Profile,
		ScanStyle:       opts.ScanStyle,
		ThreatMode:      opts.ThreatMode,
		PolicyChecks:    opts.PolicyChecks,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		RulesetHash:     opts.RulesetHash,
		Incremental:     opts.Incremental,
		FailOn:          opts.FailOn,
		MaxFiles:        opts.MaxFiles,
		MaxFindings:     opts.MaxFindings,
		RedactedMatches: opts.RedactSecrets,
	}
	if len(opts.Paths) == 1 {
		report.TargetPath = opts.Paths[0]
	}
	stateCache, err := NewIncrementalStateCache(opts.StateCachePath, opts.RulesetHash, opts.Incremental, opts.Logger)
	if err != nil {
		return model.Report{}, nil, err
	}
	if stateCache.Enabled() {
		report.StateCachePath = stateCache.Path()
	}
	return report, stateCache, nil
}

func finalizeReport(
	report *model.Report,
	opts model.ScanOptions,
	stateCache *IncrementalStateCache,
	walkComplete bool,
) error {
	if stateCache.Enabled() {
		stateCache.Finalize(walkComplete && !report.MaxFilesReached, opts.RulesetHash)
		if saveErr := stateCache.Save(); saveErr != nil {
			opts.Logger.Warnf("failed to save incremental state cache: %v", saveErr)
		}
	}

	correlated := correlation.RunCorrelation(report.Findings)
	report.Findings = append(report.Findings, correlated...)
	report.Findings = DedupeFindings(report.Findings)
	report.Findings = RollupFindings(report.Findings)
	report.Findings = FilterFindingsByThreatMode(report.Findings, opts.ThreatMode)
	report.Findings = model.FilterFindingsByMode(report.Findings, opts.Mode)
	SortFindings(report.Findings)
	report.FindingsBySeverity = SummarizeFindings(report.Findings)
	report.FindingsByConfidence = model.SummarizeFindingsByConfidence(report.Findings)
	report.Mode = opts.Mode
	report.RiskScore = ComputeRiskScore(report.Findings)
	if opts.FailOn != model.SeverityNone {
		report.ThresholdExceeded = ThresholdExceeded(report.Findings, opts.FailOn, opts.Mode)
	}
	if report.MaxFindingsReached {
		opts.Logger.Warnf(
			"finding cap reached: retained=%d dropped=%d",
			len(report.Findings),
			report.DroppedFindings,
		)
	}
	opts.Logger.Debugf(
		"scan aggregation done findings=%d dropped=%d permissions=%d",
		len(report.Findings),
		report.DroppedFindings,
		report.PermissionErrors,
	)
	report.ScanCompletedAt = time.Now().UTC().Format(time.RFC3339)
	return nil
}

// progressTracker emits periodic scan progress at debug verbosity.
type progressTracker struct {
	total    int
	done     int
	interval int
	logger   model.ScanLogger
}

func newProgressTracker(total int, logger model.ScanLogger) *progressTracker {
	interval := 1
	if total > 0 {
		interval = total / 10
		if interval < 1 {
			interval = 1
		}
		if interval > 100 {
			interval = 100
		}
	}
	return &progressTracker{total: total, interval: interval, logger: logger}
}

func (p *progressTracker) tick(scanned int) {
	p.done += scanned
	if p.done%p.interval == 0 || p.done == p.total {
		if p.total > 0 {
			pct := (p.done * 100) / p.total
			p.logger.Debugf("progress: %d/%d files scanned (%d%%)", p.done, p.total, pct)
		} else {
			p.logger.Debugf("progress: %d files scanned", p.done)
		}
	}
}

// ScanWithOptions performs bounded concurrent file scanning with report aggregation.
//
//nolint:gocyclo // scan orchestrator wiring many optional features
func ScanWithOptions(ctx context.Context, rules []model.Rule, opts model.ScanOptions) (model.Report, error) {
	if len(opts.Paths) == 0 {
		return model.Report{}, errors.New("no scan paths provided")
	}
	if opts.MaxBytes <= 0 {
		return model.Report{}, errors.New("max bytes must be > 0")
	}
	if opts.MaxFiles < 0 {
		return model.Report{}, errors.New("max files must be >= 0")
	}
	normalizeOptions(&opts, rules)
	if err := ctx.Err(); err != nil {
		return model.Report{}, err
	}

	report, stateCache, err := initScanState(opts)
	if err != nil {
		return model.Report{}, err
	}

	var progress *progressTracker
	if opts.ProgressLog {
		totalFiles := countEligibleFiles(opts, stateCache)
		opts.Logger.Debugf("scan will process ~%d eligible files across %d root(s)", totalFiles, len(opts.Paths))
		progress = newProgressTracker(totalFiles, opts.Logger)
	}

	pathRules, contentRules := SplitRulesByTarget(rules)

	var acMatcher *ACMatcher
	var acHintRules map[string][]model.Rule
	if opts.AhoCorasick {
		acHintRules = make(map[string][]model.Rule)
		var hints []string
		for _, r := range contentRules {
			if r.LiteralHint != "" {
				acHintRules[r.LiteralHint] = append(acHintRules[r.LiteralHint], r)
				hints = append(hints, r.LiteralHint)
			}
		}
		acMatcher = NewACMatcher(hints)
		if opts.Logger != nil {
			opts.Logger.Debugf("aho-corasick: built automaton with %d hint keywords from %d content rules", len(hints), len(contentRules))
		}
	}

	jobs := make(chan scanTask, opts.Workers*8)
	var workerErr error
	applyResult := func(result scanResult) {
		if result.err != nil && workerErr == nil {
			workerErr = result.err
		}
		remaining := opts.MaxFindings - len(report.Findings)
		if remaining > 0 {
			if len(result.findings) > remaining {
				report.Findings = append(report.Findings, result.findings[:remaining]...)
				report.DroppedFindings += len(result.findings) - remaining
				report.MaxFindingsReached = true
			} else {
				report.Findings = append(report.Findings, result.findings...)
			}
		} else {
			report.DroppedFindings += len(result.findings)
			if len(result.findings) > 0 {
				report.MaxFindingsReached = true
			}
		}
		report.ScannedFiles += result.scanned
		report.SkippedFiles += result.skipped
		report.PermissionErrors += result.permissionErrors

		if opts.PerfFileLog && result.scanned > 0 {
			if result.duration >= slowFileThreshold {
				opts.Logger.Debugf("SLOW %s took %s findings=%d", result.path, result.duration, len(result.findings))
			} else {
				opts.Logger.Debugf("file %s took %s findings=%d", result.path, result.duration, len(result.findings))
			}
		}

		if progress != nil && result.scanned > 0 {
			progress.tick(result.scanned)
		}

		if stateCache.Enabled() && result.err == nil {
			info, statErr := os.Stat(result.path)
			if statErr == nil && info.Mode().IsRegular() {
				fileHash := ""
				if result.scanned > 0 {
					if computed, hashErr := security.SHA256FileHex(result.path); hashErr == nil {
						fileHash = computed
					}
				}
				stateCache.Record(result.path, info, fileHash)
			}
		}
	}

	results := startWorkers(ctx, opts.Workers, jobs, pathRules, contentRules, opts, acMatcher, acHintRules)
	walkComplete, walkErr := walkAndEnqueue(ctx, opts, stateCache, &report, jobs, results, applyResult)

	close(jobs)
	for result := range results {
		applyResult(result)
	}

	if walkErr != nil {
		return model.Report{}, walkErr
	}
	if workerErr != nil {
		return model.Report{}, workerErr
	}
	if err := finalizeReport(&report, opts, stateCache, walkComplete); err != nil {
		return model.Report{}, err
	}
	return report, nil
}

// SplitRulesByTarget partitions path and content rules for faster evaluation loops.
func SplitRulesByTarget(rules []model.Rule) ([]model.Rule, []model.Rule) {
	pathRules := make([]model.Rule, 0, len(rules))
	contentRules := make([]model.Rule, 0, len(rules))
	for _, rule := range rules {
		switch rule.Target {
		case model.TargetPath:
			pathRules = append(pathRules, rule)
		case model.TargetContent:
			contentRules = append(contentRules, rule)
		}
	}
	return pathRules, contentRules
}

// DedupeFindings removes duplicate entries caused by overlapping checks.
func DedupeFindings(in []model.Finding) []model.Finding {
	out := make([]model.Finding, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, finding := range in {
		key := fmt.Sprintf("%s|%s|%d|%s", finding.RuleID, finding.File, finding.Line, finding.Match)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, finding)
	}
	return out
}

// ThresholdExceeded checks whether any finding meets the configured fail threshold.
func ThresholdExceeded(findings []model.Finding, failOn model.Severity, mode model.ScanMode) bool {
	if failOn == model.SeverityNone {
		return false
	}
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		if model.SeverityWeight(finding.Severity) < model.SeverityWeight(failOn) {
			continue
		}
		if mode != "" && !model.IsGateEligible(finding.RuleID, mode) {
			continue
		}
		return true
	}
	return false
}

// SummarizeFindings counts findings by severity for compact report statistics.
func SummarizeFindings(findings []model.Finding) map[string]int {
	out := map[string]int{
		string(model.SeverityCritical): 0,
		string(model.SeverityHigh):     0,
		string(model.SeverityMedium):   0,
		string(model.SeverityLow):      0,
		string(model.SeverityInfo):     0,
	}
	for _, finding := range findings {
		if finding.Suppressed {
			continue
		}
		out[string(finding.Severity)]++
	}
	return out
}

// SortFindings applies deterministic finding ordering for reproducible output.
func SortFindings(findings []model.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		a := findings[i]
		b := findings[j]
		if model.SeverityWeight(a.Severity) != model.SeverityWeight(b.Severity) {
			return model.SeverityWeight(a.Severity) > model.SeverityWeight(b.Severity)
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

type scanFileOpts struct {
	MaxBytes               int64
	UseAbsolutePath        bool
	IgnorePermissionErrors bool
	RedactSecrets          bool
	MaxFindingsPerFile     int
	ScanStyle              model.ScanStyle
	ThreatMode             model.ThreatMode
	PolicyChecks           bool
	ACMatcher              *ACMatcher
	ACHintRules            map[string][]model.Rule
	NFKC                   bool
	MaxDecodeDepth         int
	XORBrute               bool
}

type scanFileResult struct {
	findings         []model.Finding
	scanned          int
	skipped          int
	permissionErrors int
	err              error
}

// ScanFileOptions configures per-file scanning behavior.
type ScanFileOptions = scanFileOpts

// ScanFileResult captures per-file scan output.
type ScanFileResult struct {
	Findings         []model.Finding
	Scanned          int
	Skipped          int
	PermissionErrors int
	Err              error
}

// Package model defines the shared domain types for skeptic.
// It has zero intra-project dependencies and relies only on stdlib.
package model

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Severity represents the severity level of a finding (info through critical, or none for gating bypass).
type Severity string

// Severity constants from info (lowest) through critical (highest), plus none for gating bypass.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityNone     Severity = "none"
)

var severityRank = map[Severity]int{
	SeverityInfo:     1,
	SeverityLow:      2,
	SeverityMedium:   3,
	SeverityHigh:     4,
	SeverityCritical: 5,
	SeverityNone:     0,
}

// SeverityWeight returns the numeric rank for a severity level.
// Higher values indicate more severe findings.
func SeverityWeight(s Severity) int {
	return severityRank[s]
}

// ParseSeverity converts a raw string into a validated Severity value.
func ParseSeverity(raw string) (Severity, error) {
	s := Severity(strings.ToLower(strings.TrimSpace(raw)))
	switch s {
	case SeverityNone, SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return s, nil
	default:
		return "", fmt.Errorf("expected one of none|info|low|medium|high|critical, got %q", raw)
	}
}

// OutputFormat is the scanner report output format (text, JSON, SARIF, or Markdown).
type OutputFormat string

// OutputFormat constants for each supported report format.
const (
	FormatText     OutputFormat = "text"
	FormatJSON     OutputFormat = "json"
	FormatSARIF    OutputFormat = "sarif"
	FormatMarkdown OutputFormat = "markdown"
)

// RuleTarget selects whether a rule matches file content or file paths.
type RuleTarget string

// RuleTarget constants selecting content-based or path-based matching.
const (
	TargetContent RuleTarget = "content"
	TargetPath    RuleTarget = "path"
)

// ScanProfile selects which scan preset applies (repository layout, developer, container, or full filesystem).
type ScanProfile string

// ScanProfile constants for each supported filesystem scanning scope.
const (
	ProfileRepo      ScanProfile = "repo"
	ProfileDeveloper ScanProfile = "developer"
	ProfileContainer ScanProfile = "container"
	ProfileFullFS    ScanProfile = "fullfs"
)

// ParseProfile parses a scan profile string (case-insensitive) into a ScanProfile value.
func ParseProfile(raw string) (ScanProfile, error) {
	profile := ScanProfile(strings.ToLower(strings.TrimSpace(raw)))
	switch profile {
	case ProfileRepo, ProfileDeveloper, ProfileContainer, ProfileFullFS:
		return profile, nil
	default:
		return "", fmt.Errorf("expected one of repo|developer|container|fullfs, got %q", raw)
	}
}

// ScanStyle selects pattern-only, behavior-only, or hybrid scanning.
type ScanStyle string

// ScanStyle constants for each detection methodology.
const (
	ScanStylePattern  ScanStyle = "pattern"
	ScanStyleBehavior ScanStyle = "behavior"
	ScanStyleHybrid   ScanStyle = "hybrid"
)

// ParseScanStyle parses a scan style string (case-insensitive); empty input defaults to pattern.
func ParseScanStyle(raw string) (ScanStyle, error) {
	style := ScanStyle(strings.ToLower(strings.TrimSpace(raw)))
	if style == "" {
		style = ScanStylePattern
	}
	switch style {
	case ScanStylePattern, ScanStyleBehavior, ScanStyleHybrid:
		return style, nil
	default:
		return "", fmt.Errorf("expected one of pattern|behavior|hybrid, got %q", raw)
	}
}

// ScanStyleUsesPattern reports whether the given style runs pattern-based rule matching.
func ScanStyleUsesPattern(style ScanStyle) bool {
	return style == ScanStylePattern || style == ScanStyleHybrid
}

// ScanStyleUsesBehavior reports whether the given style runs behavior checks.
func ScanStyleUsesBehavior(style ScanStyle) bool {
	return style == ScanStyleBehavior || style == ScanStyleHybrid
}

// ThreatMode narrows reported findings to all rules, machine-identity focus, or AI/agent workload focus.
type ThreatMode string

// ThreatMode constants for each detection focus area.
const (
	ThreatModeAll             ThreatMode = "all"
	ThreatModeMachineIdentity ThreatMode = "machine-identity"
	ThreatModeAIWorkload      ThreatMode = "ai-workload"
)

// ParseThreatMode parses a threat mode string (case-insensitive); empty input defaults to all.
func ParseThreatMode(raw string) (ThreatMode, error) {
	mode := ThreatMode(strings.ToLower(strings.TrimSpace(raw)))
	if mode == "" {
		mode = ThreatModeAll
	}
	switch mode {
	case ThreatModeAll, ThreatModeMachineIdentity, ThreatModeAIWorkload:
		return mode, nil
	default:
		return "", fmt.Errorf("expected one of all|machine-identity|ai-workload, got %q", raw)
	}
}

// ConfidenceClass categorizes a finding's epistemic strength.
type ConfidenceClass string

// ConfidenceClass constants ranking finding reliability from definitive through correlated.
const (
	ConfidenceDefinitive ConfidenceClass = "definitive"
	ConfidenceHeuristic  ConfidenceClass = "heuristic"
	ConfidenceCorrelated ConfidenceClass = "correlated"
)

// ParseConfidenceClass parses a confidence class string (case-insensitive).
func ParseConfidenceClass(raw string) (ConfidenceClass, error) {
	c := ConfidenceClass(strings.ToLower(strings.TrimSpace(raw)))
	switch c {
	case ConfidenceDefinitive, ConfidenceHeuristic, ConfidenceCorrelated, "":
		return c, nil
	default:
		return "", fmt.Errorf("expected one of definitive|heuristic|correlated, got %q", raw)
	}
}

// RuleFamily declares how one rule-ID prefix is classified. Confidence and gate
// eligibility are declared together, in one table, so a family cannot be
// definitive-confidence and silently ungated — that split is what let
// HIGH/definitive CLOUD-ID and POL-GHA findings pass a `--fail-on high` run.
type RuleFamily struct {
	// Prefix is the uppercase rule-ID prefix, including the trailing dash.
	Prefix string
	// Confidence is the default class for findings in this family that do not
	// set ConfidenceClass explicitly.
	Confidence ConfidenceClass
	// GatesInDeveloper reports whether findings in this family can cross the
	// --fail-on threshold in developer mode.
	GatesInDeveloper bool
	// UngatedReason explains why a definitive family does not gate. It must be
	// non-empty whenever Confidence is definitive and GatesInDeveloper is false;
	// TestDefinitiveFamiliesGateOrExplain enforces that.
	UngatedReason string
}

// ruleFamilies is the single source of truth for confidence defaults and
// developer-mode gate eligibility.
//
// Invariants, enforced by tests in this package:
//   - every Prefix is emitted by at least one rule, check, or bundled rulepack
//   - definitive families either gate or carry an UngatedReason
//
// Adding a prefix here without shipping a rule that emits it makes the gate look
// broader than it is; three such phantom families (CI-MUTABLE-, CI-EXEC-,
// NON-CODE-) were removed when this table was introduced.
var ruleFamilies = []RuleFamily{
	// Agentic ecosystem poisoning — the primary wedge.
	{Prefix: "AGT-TRUST-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},
	{Prefix: "AGT-MEM-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},
	{Prefix: "AGT-OUT-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},
	{Prefix: "AGT-SKL-", Confidence: ConfidenceHeuristic, GatesInDeveloper: true},
	{Prefix: "AGT-MCP-", Confidence: ConfidenceHeuristic, GatesInDeveloper: true},
	{Prefix: "DISC-MCP-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},

	// CI/CD trust boundaries.
	{Prefix: "CI-PRT-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},
	{Prefix: "CI-EXFIL-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},
	{Prefix: "CI-ABUSE-", Confidence: ConfidenceHeuristic, GatesInDeveloper: true},
	{Prefix: "CI-SECRET-", Confidence: ConfidenceHeuristic, GatesInDeveloper: true},
	{Prefix: "POL-GHA-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},

	// Supply chain structural hygiene.
	{Prefix: "SCM-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},
	{Prefix: "DOM-TYPO-", Confidence: ConfidenceHeuristic, GatesInDeveloper: true},

	// Machine identity.
	{Prefix: "GRAPH-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},
	{Prefix: "CLOUD-ID-", Confidence: ConfidenceDefinitive, GatesInDeveloper: true},

	// Correlation output. Correlated findings are derived from other findings;
	// gating on them would double-count whatever already gated underneath.
	{
		Prefix: "COR-", Confidence: ConfidenceCorrelated, GatesInDeveloper: false,
		UngatedReason: "derived from other findings; the underlying finding gates instead",
	},
	{
		Prefix: "DRIFT-", Confidence: ConfidenceCorrelated, GatesInDeveloper: false,
		UngatedReason: "drift is a trend signal against a baseline, not a standalone defect",
	},
}

// lookupRuleFamily returns the longest matching family for a rule ID.
// Longest-match keeps a specific prefix (CI-PRT-) authoritative over any
// broader one that might later be added (CI-).
func lookupRuleFamily(ruleID string) (RuleFamily, bool) {
	upper := strings.ToUpper(strings.TrimSpace(ruleID))
	var best RuleFamily
	found := false
	for _, fam := range ruleFamilies {
		if !strings.HasPrefix(upper, fam.Prefix) {
			continue
		}
		if !found || len(fam.Prefix) > len(best.Prefix) {
			best = fam
			found = true
		}
	}
	return best, found
}

// RuleFamilies returns a copy of the declared rule-family table.
func RuleFamilies() []RuleFamily {
	out := make([]RuleFamily, len(ruleFamilies))
	copy(out, ruleFamilies)
	return out
}

// DefaultConfidenceForRuleID derives confidence class from a rule ID prefix.
// Structural wedge rules default to definitive; broad pattern/behavioral rules
// default to heuristic; correlation rules default to correlated.
func DefaultConfidenceForRuleID(ruleID string) ConfidenceClass {
	if fam, ok := lookupRuleFamily(ruleID); ok {
		return fam.Confidence
	}
	return ConfidenceHeuristic
}

// --- ScanMode ---

// ScanMode selects the user-facing operating mode. Modes sit above presets.
type ScanMode string

// ScanMode constants for each operating mode (developer, IR triage, deep analysis).
const (
	ScanModeDeveloper ScanMode = "developer"
	ScanModeIR        ScanMode = "ir"
	ScanModeDeep      ScanMode = "deep"
)

// ParseScanMode parses a scan mode string; empty defaults to developer.
func ParseScanMode(raw string) (ScanMode, error) {
	m := ScanMode(strings.ToLower(strings.TrimSpace(raw)))
	if m == "" {
		m = ScanModeDeveloper
	}
	switch m {
	case ScanModeDeveloper, ScanModeIR, ScanModeDeep:
		return m, nil
	default:
		return "", fmt.Errorf("expected one of developer|ir|deep, got %q", raw)
	}
}

// IsGateEligible reports whether a rule family can trigger build failure
// in the given mode. Only wedge-family findings gate in developer mode.
func IsGateEligible(ruleID string, mode ScanMode) bool {
	if mode == "" {
		return true
	}
	switch mode {
	case ScanModeDeveloper:
		fam, ok := lookupRuleFamily(ruleID)
		return ok && fam.GatesInDeveloper
	case ScanModeIR, ScanModeDeep:
		return false
	default:
		return true
	}
}

// GateSuppressedRuleIDs returns the distinct rule IDs that met the severity
// threshold but were excluded from gating by family eligibility, in first-seen
// order. Callers surface these so a passing run never hides the fact that
// qualifying findings were present — silent fail-open is the worst property a
// security gate can have.
func GateSuppressedRuleIDs(findings []Finding, failOn Severity, mode ScanMode) []string {
	if failOn == SeverityNone || mode == "" {
		return nil
	}
	seen := make(map[string]struct{}, 8)
	var out []string
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		if SeverityWeight(f.Severity) < SeverityWeight(failOn) {
			continue
		}
		if IsGateEligible(f.RuleID, mode) {
			continue
		}
		if _, dup := seen[f.RuleID]; dup {
			continue
		}
		seen[f.RuleID] = struct{}{}
		out = append(out, f.RuleID)
	}
	return out
}

// FilterFindingsByMode applies mode-driven presentation filtering.
// This is a display decision, not a detection decision — correlation
// runs on the full unfiltered set before this is applied.
func FilterFindingsByMode(findings []Finding, mode ScanMode) []Finding {
	switch mode {
	case ScanModeDeveloper:
		filtered := make([]Finding, 0, len(findings))
		for _, f := range findings {
			cc := f.ConfidenceClass
			switch cc {
			case ConfidenceDefinitive, ConfidenceCorrelated:
				filtered = append(filtered, f)
			default:
				if SeverityWeight(f.Severity) >= SeverityWeight(SeverityCritical) {
					filtered = append(filtered, f)
				}
			}
		}
		return filtered
	case ScanModeIR, ScanModeDeep:
		return findings
	default:
		return findings
	}
}

// SummarizeFindingsByConfidence counts findings per confidence class.
func SummarizeFindingsByConfidence(findings []Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		if f.Suppressed {
			continue
		}
		cc := string(f.ConfidenceClass)
		if cc == "" {
			cc = string(ConfidenceHeuristic)
		}
		counts[cc]++
	}
	return counts
}

// RuleQualityMode controls how rule quality validation failures are handled (off, warn, or strict).
type RuleQualityMode string

// RuleQualityMode constants for each quality validation behavior.
const (
	RuleQualityOff    RuleQualityMode = "off"
	RuleQualityWarn   RuleQualityMode = "warn"
	RuleQualityStrict RuleQualityMode = "strict"
)

// --- Core domain types ---

// CompiledPattern is the interface for compiled rule-pattern matchers.
type CompiledPattern interface {
	MatchString(s string) bool
}

// Rule is a compiled scanner rule: metadata, pattern, and optional path/context matchers.
type Rule struct {
	ID              string
	Title           string
	Description     string
	Category        string
	Mitre           string
	Severity        Severity
	ConfidenceClass ConfidenceClass // optional override; empty = derive from rule ID prefix
	Pattern         string
	Target          RuleTarget
	Remediation     string
	RE              CompiledPattern `json:"-"`
	LiteralHint     string          `json:"-"`
	PathPattern     *regexp.Regexp  `json:"-"`
	ContextPattern  *regexp.Regexp  `json:"-"`
	ContextWindow   int             `json:"-"`
	ExcludePattern  *regexp.Regexp  `json:"-"` // syntactic negative match — suppress when line matches
}

// Finding is a single match emitted for a rule, including location, snippet, and optional baseline state.
type Finding struct {
	RuleID            string          `json:"rule_id"`
	Title             string          `json:"title"`
	Description       string          `json:"description"`
	Category          string          `json:"category"`
	Mitre             string          `json:"mitre"`
	Severity          Severity        `json:"severity"`
	File              string          `json:"file"`
	Line              int             `json:"line,omitempty"`
	Match             string          `json:"match"`
	EncodingChain     string          `json:"encoding_chain,omitempty"`
	References        []string        `json:"references,omitempty"`
	RelatedRuleIDs    []string        `json:"related_rule_ids,omitempty"`
	BaselineState     string          `json:"baseline_state,omitempty"`
	Confidence        float64         `json:"confidence,omitempty"`
	ConfidenceClass   ConfidenceClass `json:"confidence_class,omitempty"`
	Remediation       string          `json:"remediation,omitempty"`
	Suppressed        bool            `json:"suppressed,omitempty"`
	SuppressionReason string          `json:"suppression_reason,omitempty"`
}

// Report is the aggregated scan result: targets, counts, findings, and baseline diff summary.
type Report struct {
	TargetPath   string      `json:"target_path,omitempty"`
	TargetPaths  []string    `json:"target_paths"`
	Profile      ScanProfile `json:"profile"`
	ScanStyle    ScanStyle   `json:"scan_style"`
	ThreatMode   ThreatMode  `json:"threat_mode"`
	Mode         ScanMode    `json:"mode,omitempty"`
	PolicyChecks bool        `json:"policy_checks"`
	GeneratedAt  string      `json:"generated_at"`
	// ScanCompletedAt is when scan aggregation finished (UTC RFC3339), for SARIF run timing.
	ScanCompletedAt string `json:"scan_completed_at,omitempty"`
	// ToolVersion is the scanner build identity string included in SARIF tool.driver.version.
	ToolVersion          string         `json:"tool_version,omitempty"`
	ToolInformationURI   string         `json:"tool_information_uri,omitempty"`
	SARIFBasePath        string         `json:"sarif_base_path,omitempty"`
	RulesetHash          string         `json:"ruleset_hash,omitempty"`
	Incremental          bool           `json:"incremental"`
	StateCachePath       string         `json:"state_cache_path,omitempty"`
	CacheSkippedFiles    int            `json:"cache_skipped_files"`
	ScannedFiles         int            `json:"scanned_files"`
	SkippedFiles         int            `json:"skipped_files"`
	PermissionErrors     int            `json:"permission_errors"`
	MaxFiles             int            `json:"max_files,omitempty"`
	MaxFilesReached      bool           `json:"max_files_reached"`
	MaxFindings          int            `json:"max_findings,omitempty"`
	MaxFindingsReached   bool           `json:"max_findings_reached"`
	DroppedFindings      int            `json:"dropped_findings"`
	RedactedMatches      bool           `json:"redacted_matches"`
	Findings             []Finding      `json:"findings"`
	FindingsBySeverity   map[string]int `json:"findings_by_severity"`
	FindingsByConfidence map[string]int `json:"findings_by_confidence,omitempty"`
	BaselinePath         string         `json:"baseline_path,omitempty"`
	DiffOnly             bool           `json:"diff_only"`
	NewFindings          int            `json:"new_findings"`
	UnchangedFindings    int            `json:"unchanged_findings"`
	ResolvedFindings     int            `json:"resolved_findings"`
	FailOn               Severity       `json:"fail_on"`
	ThresholdExceeded    bool           `json:"threshold_exceeded"`
	RiskScore            int            `json:"risk_score"`
}

// ScanLogger is an interface that decouples scan options from the concrete Logger implementation.
type ScanLogger interface {
	Errorf(format string, args ...any)
	Warnf(format string, args ...any)
	Infof(format string, args ...any)
	Debugf(format string, args ...any)
}

// ScanOptions holds per-run scan configuration passed from the CLI or daemon into the engine.
type ScanOptions struct {
	Paths                  []string
	Profile                ScanProfile
	ScanStyle              ScanStyle
	ThreatMode             ThreatMode
	Mode                   ScanMode
	PolicyChecks           bool
	MaxBytes               int64
	FailOn                 Severity
	IgnorePermissionErrors bool
	MaxFiles               int
	Workers                int
	MaxFindings            int
	MaxFindingsPerFile     int
	RedactSecrets          bool
	Incremental            bool
	StateCachePath         string
	RulesetHash            string
	Logger                 ScanLogger
	ProgressLog            bool
	PerfFileLog            bool
	IncludeRules           []string
	ExcludeRules           []string
	IgnorePaths            []string
	AhoCorasick            bool
	NFKC                   bool
	ToolName               string
	// MaxDecodeDepth limits recursive payload decoding (default 3). Values <= 0 use the default.
	MaxDecodeDepth int
	// XORBrute enables single-byte XOR brute-force on high-entropy file content after normal decoders.
	XORBrute bool
}

// RuleSpec is the JSON-serializable representation of a rule in a signed rule pack.
type RuleSpec struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	Category        string          `json:"category"`
	Mitre           string          `json:"mitre"`
	Severity        Severity        `json:"severity"`
	ConfidenceClass ConfidenceClass `json:"confidence_class,omitempty"`
	Pattern         string          `json:"pattern"`
	Target          RuleTarget      `json:"target"`
	Remediation     string          `json:"remediation,omitempty"`
}

// RulePack is a versioned bundle of rule specifications and optional provenance metadata.
type RulePack struct {
	Version     int        `json:"version"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	GeneratedAt string     `json:"generated_at"`
	Sources     []string   `json:"sources,omitempty"`
	Ecosystems  []string   `json:"ecosystems,omitempty"`
	Rules       []RuleSpec `json:"rules"`
}

// RuleTestCase defines an inline assertion for a single rule in a test pack.
type RuleTestCase struct {
	RuleID         string   `json:"rule_id"`
	ShouldMatch    []string `json:"should_match"`
	ShouldNotMatch []string `json:"should_not_match,omitempty"`
}

// RuleTestPack is a versioned bundle of inline test assertions for a rule pack.
type RuleTestPack struct {
	Version   int            `json:"version"`
	Name      string         `json:"name"`
	RulesFile string         `json:"rules_file"`
	Tests     []RuleTestCase `json:"tests"`
}

// --- Utilities ---

// ExpandHomePath resolves ~ prefixes to the user's home directory.
func ExpandHomePath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return path
		}
		if path == "~" {
			return home
		}
		// filepath.Join, not concatenation: path[1:] carries a forward slash,
		// which would produce "C:\Users\me/foo/bar" on Windows.
		return filepath.Join(home, path[2:])
	}
	return path
}

// CompactSnippet normalizes line snippets into bounded, report-friendly text.
func CompactSnippet(line string) string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.Join(strings.Fields(trimmed), " ")
	const max = 200
	if len(trimmed) <= max {
		return trimmed
	}
	return trimmed[:max] + "..."
}

// SortedMapKeys returns sorted keys from a set map for deterministic iteration.
func SortedMapKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

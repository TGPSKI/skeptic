package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/config"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/rules"
)

const maxLineBytes = 2 * 1024 * 1024

// ingestExitCode attaches a CLI exit code (1 or 2) to a user-facing error message.
type ingestExitCode struct {
	code int
	msg  string
}

// Error returns the user-facing error message.
func (e *ingestExitCode) Error() string { return e.msg }

// StringListFlag is a repeatable CLI flag that accumulates values into a string slice.
type StringListFlag []string

// String returns the comma-joined representation required by flag.Value.
func (s *StringListFlag) String() string {
	return strings.Join(*s, ",")
}

// Set appends a normalized value for repeatable CLI flags.
func (s *StringListFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*s = append(*s, value)
	return nil
}

// SourceDocument pairs a source identifier (URL or file path) with its fetched content.
type SourceDocument struct {
	Source  string
	Content string
}

// GeneratedRule wraps a model.Rule produced by the ingest pipeline from threat intelligence sources.
type GeneratedRule struct {
	model.Rule
}

// ingestConfig holds parsed CLI flags and runtime handles for the ingest pipeline.
type ingestConfig struct {
	sources               []string
	sourcesFile           string
	allowHosts            []string
	outPath               string
	packName              string
	description           string
	ecosystemsRaw         string
	maxRules              int
	minSeverity           model.Severity
	ruleQualityMode       model.RuleQualityMode
	timeoutSec            int
	maxSourceBytes        int64
	maxFilesPerSourceDir  int
	strictSourceRead      bool
	includeCommandHeur    bool
	includeContextualIocs bool
	allowHTTP             bool
	maxRedirects          int
	inputFormat           string
	logger                *logging.Logger
	logCloser             io.Closer

	generateTests bool

	mergedSources []string
	ecoSet        map[string]struct{}
}

func parseIngestFlags(args []string, stderr io.Writer) (ingestConfig, error) {
	var (
		sourcesFlag           StringListFlag
		allowHostsFlag        StringListFlag
		sourcesFile           string
		outPath               string
		packName              string
		description           string
		ecosystemsRaw         string
		maxRules              int
		minSeverityRaw        string
		timeoutSec            int
		maxSourceBytes        int64
		maxFilesPerSourceDir  int
		strictSourceRead      bool
		includeCommandHeur    bool
		includeContextualIocs bool
		allowHTTP             bool
		maxRedirects          int
		ruleQualityRaw        string
		verbosity             int
		quiet                 bool
		logFilePath           string
		inputFormat           string
	)

	fs := flag.NewFlagSet("skeptic ingest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		config.PrintFormattedFlags(fs, stderr, map[string]string{
			"o": "out", "n": "name", "e": "ecosystems", "f": "input-format",
		}, nil)
	}
	fs.Var(&sourcesFlag, "source", "url, file, or directory to ingest (repeatable)")
	fs.Var(&sourcesFlag, "s", "url, file, or directory to ingest (repeatable)")
	fs.Var(&allowHostsFlag, "allow-host", "allowed hostname for URL fetch (repeatable)")
	fs.Var(&allowHostsFlag, "H", "allowed hostname (repeatable)")
	fs.StringVar(&sourcesFile, "sources-file", "", "newline-delimited source list path")
	fs.StringVar(&outPath, "out", "rulepacks/campaigns/ingested-rules.json", "output rule pack JSON path")
	fs.StringVar(&outPath, "o", "rulepacks/campaigns/ingested-rules.json", "output rule pack JSON path")
	fs.StringVar(&packName, "name", "", "rule pack name")
	fs.StringVar(&packName, "n", "", "rule pack name")
	fs.StringVar(&description, "description", "", "rule pack description")
	fs.StringVar(&ecosystemsRaw, "ecosystems", "general,pypi,npm,github-actions,container,mcp,agent-skills,go,cargo", "comma-separated ecosystems to extract")
	fs.StringVar(&ecosystemsRaw, "e", "general,pypi,npm,github-actions,container,mcp,agent-skills,go,cargo", "comma-separated ecosystems to extract")
	fs.IntVar(&maxRules, "max-rules", 500, "max generated rules")
	fs.StringVar(&minSeverityRaw, "min-severity", string(model.SeverityMedium), "minimum severity: info|low|medium|high|critical")
	fs.IntVar(&timeoutSec, "timeout-sec", 20, "HTTP timeout in seconds")
	fs.Int64Var(&maxSourceBytes, "max-source-bytes", 2*1024*1024, "max bytes per source document")
	fs.IntVar(&maxFilesPerSourceDir, "max-files-per-dir", 200, "max files per directory source")
	fs.BoolVar(&strictSourceRead, "strict", false, "fail if any source is unreadable")
	fs.BoolVar(&includeCommandHeur, "include-command-heuristics", true, "include suspicious command regex rules")
	fs.BoolVar(&includeContextualIocs, "include-contextual-iocs", true, "generate IOC rules from risk-context lines")
	fs.BoolVar(&allowHTTP, "allow-http", false, "allow plain HTTP URLs (not recommended)")
	fs.IntVar(&maxRedirects, "max-redirects", 5, "max HTTP redirect hops")
	fs.StringVar(&inputFormat, "input-format", "auto", "input format: auto|stix|sigma|yara")
	fs.StringVar(&inputFormat, "f", "auto", "input format: auto|stix|sigma|yara")
	fs.StringVar(&ruleQualityRaw, "rule-quality", string(model.RuleQualityWarn), "quality mode: off|warn|strict")
	fs.IntVar(&verbosity, "verbose", 0, "verbosity: 0=warn, 1=info, 2=debug")
	fs.BoolVar(&quiet, "quiet", false, "suppress non-error output")
	fs.StringVar(&logFilePath, "log-file", "", "write logs to file (empty = stderr only)")

	var generateTests bool
	fs.BoolVar(&generateTests, "generate-tests", false, "emit test stub alongside rule pack")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ingestConfig{}, flag.ErrHelp
		}
		return ingestConfig{}, err
	}

	minSeverity, err := model.ParseSeverity(minSeverityRaw)
	if err != nil || minSeverity == model.SeverityNone {
		return ingestConfig{}, &ingestExitCode{code: 2, msg: fmt.Sprintf("invalid --min-severity: %q", minSeverityRaw)}
	}
	if maxRules <= 0 {
		return ingestConfig{}, &ingestExitCode{code: 2, msg: "--max-rules must be > 0"}
	}
	if timeoutSec <= 0 {
		return ingestConfig{}, &ingestExitCode{code: 2, msg: "--timeout-sec must be > 0"}
	}
	if maxSourceBytes <= 0 {
		return ingestConfig{}, &ingestExitCode{code: 2, msg: "--max-source-bytes must be > 0"}
	}
	if maxFilesPerSourceDir <= 0 {
		return ingestConfig{}, &ingestExitCode{code: 2, msg: "--max-files-per-dir must be > 0"}
	}
	if maxRedirects < 0 {
		return ingestConfig{}, &ingestExitCode{code: 2, msg: "--max-redirects must be >= 0"}
	}
	switch strings.ToLower(strings.TrimSpace(inputFormat)) {
	case "auto", "stix", "sigma", "yara":
	default:
		return ingestConfig{}, &ingestExitCode{code: 2, msg: fmt.Sprintf("invalid --input-format: expected auto|stix|sigma|yara, got %q", inputFormat)}
	}
	ruleQualityMode, err := rules.ParseRuleQualityMode(ruleQualityRaw)
	if err != nil {
		return ingestConfig{}, &ingestExitCode{code: 2, msg: fmt.Sprintf("invalid --rule-quality: %v", err)}
	}

	logger, logCloser, err := logging.SetupLogger(stderr, logFilePath, quiet, verbosity)
	if err != nil {
		return ingestConfig{}, &ingestExitCode{code: 1, msg: fmt.Sprintf("failed to initialize logger: %v", err)}
	}

	sources := make([]string, len(sourcesFlag))
	copy(sources, sourcesFlag)
	allowHosts := make([]string, len(allowHostsFlag))
	copy(allowHosts, allowHostsFlag)

	return ingestConfig{
		sources:               sources,
		sourcesFile:           sourcesFile,
		allowHosts:            allowHosts,
		outPath:               outPath,
		packName:              packName,
		description:           description,
		ecosystemsRaw:         ecosystemsRaw,
		maxRules:              maxRules,
		minSeverity:           minSeverity,
		ruleQualityMode:       ruleQualityMode,
		timeoutSec:            timeoutSec,
		maxSourceBytes:        maxSourceBytes,
		maxFilesPerSourceDir:  maxFilesPerSourceDir,
		strictSourceRead:      strictSourceRead,
		includeCommandHeur:    includeCommandHeur,
		includeContextualIocs: includeContextualIocs,
		allowHTTP:             allowHTTP,
		maxRedirects:          maxRedirects,
		inputFormat:           inputFormat,
		generateTests:         generateTests,
		logger:                logger,
		logCloser:             logCloser,
	}, nil
}

func loadIngestSources(ctx context.Context, cfg *ingestConfig, stderr io.Writer) ([]SourceDocument, error) {
	allSources := make([]string, 0, len(cfg.sources)+8)
	allSources = append(allSources, cfg.sources...)
	if strings.TrimSpace(cfg.sourcesFile) != "" {
		loaded, err := ReadSourcesFile(cfg.sourcesFile)
		if err != nil {
			return nil, &ingestExitCode{code: 2, msg: fmt.Sprintf("failed to read --sources-file: %v", err)}
		}
		allSources = append(allSources, loaded...)
	}
	if len(allSources) == 0 {
		return nil, &ingestExitCode{code: 2, msg: "at least one --source or --sources-file is required"}
	}
	allSources = DedupeStrings(allSources)
	cfg.mergedSources = allSources

	hasURLSource := false
	for _, source := range allSources {
		lower := strings.ToLower(strings.TrimSpace(source))
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			hasURLSource = true
			break
		}
	}
	if cfg.allowHTTP {
		cfg.logger.Warnf("ingest HTTP mode enabled: plaintext threat-intel transport increases tampering risk")
	}
	if hasURLSource && len(cfg.allowHosts) == 0 {
		return nil, &ingestExitCode{code: 2, msg: "URL sources require --allow-host to be set (deny-all by default); specify allowed hostnames to proceed"}
	}

	ecosystems := DedupeStrings(rules.SplitCSV(cfg.ecosystemsRaw))
	if len(ecosystems) == 0 {
		return nil, &ingestExitCode{code: 2, msg: "no ecosystems selected"}
	}
	ecoSet := make(map[string]struct{}, len(ecosystems))
	for _, ecosystem := range ecosystems {
		ecoSet[strings.ToLower(strings.TrimSpace(ecosystem))] = struct{}{}
	}
	cfg.ecoSet = ecoSet

	docs, warnings, err := LoadSourceDocuments(ctx, allSources, SourceLoadOptions{
		MaxSourceBytes: cfg.maxSourceBytes,
		MaxFilesPerDir: cfg.maxFilesPerSourceDir,
		Timeout:        time.Duration(cfg.timeoutSec) * time.Second,
		AllowHTTP:      cfg.allowHTTP,
		MaxRedirects:   cfg.maxRedirects,
		AllowedHosts:   DedupeStrings(cfg.allowHosts),
		Logger:         cfg.logger,
	})
	if err != nil {
		return nil, &ingestExitCode{code: 1, msg: fmt.Sprintf("failed to load sources: %v", err)}
	}
	if cfg.strictSourceRead && len(warnings) > 0 {
		for _, warning := range warnings {
			cfg.logger.Warnf("source warning: %s", warning)
			fmt.Fprintf(stderr, "source warning: %s\n", warning)
		}
		return nil, &ingestExitCode{code: 1, msg: ""}
	}
	for _, warning := range warnings {
		cfg.logger.Warnf("source warning: %s", warning)
		fmt.Fprintf(stderr, "source warning: %s\n", warning)
	}
	if len(docs) == 0 {
		return nil, &ingestExitCode{code: 1, msg: "no readable source content found"}
	}
	return docs, nil
}

func processIngestSources(cfg ingestConfig, docs []SourceDocument, stderr io.Writer) (model.RulePack, error) {
	_ = stderr
	// Structured threat-intel feed processing: parse STIX/Sigma/YARA before heuristic extraction
	var feedRules []model.Rule
	var heuristicDocs []SourceDocument
	for _, doc := range docs {
		feedFmt := DetectFeedFormat(cfg.inputFormat, doc.Content)
		switch feedFmt {
		case "stix":
			cfg.logger.Infof("parsing STIX bundle: %s", doc.Source)
			stixRules, stixErr := ParseSTIXBundle([]byte(doc.Content))
			if stixErr != nil {
				cfg.logger.Warnf("skipping STIX source %s: %v", doc.Source, stixErr)
			}
			feedRules = append(feedRules, stixRules...)
		case "sigma":
			cfg.logger.Infof("parsing Sigma rule: %s", doc.Source)
			feedRules = append(feedRules, ParseSigmaRule([]byte(doc.Content))...)
		case "yara":
			cfg.logger.Infof("parsing YARA rule: %s", doc.Source)
			feedRules = append(feedRules, ParseYARAStrings([]byte(doc.Content))...)
		default:
			heuristicDocs = append(heuristicDocs, doc)
		}
	}
	if len(feedRules) > 0 {
		cfg.logger.Infof("extracted %d rules from structured threat-intel feeds", len(feedRules))
	}

	pack := buildIngestedRulePack(heuristicDocs, cfg.mergedSources, cfg.ecoSet, ingestOptions{
		MaxRules:             cfg.maxRules,
		MinSeverity:          cfg.minSeverity,
		IncludeCommandHeur:   cfg.includeCommandHeur,
		IncludeContextualIoc: cfg.includeContextualIocs,
		Name:                 cfg.packName,
		Description:          cfg.description,
	})
	// Merge structured feed rules into the pack
	for _, r := range feedRules {
		pack.Rules = append(pack.Rules, model.RuleSpec{
			ID:          r.ID,
			Pattern:     r.Pattern,
			Target:      r.Target,
			Title:       r.Title,
			Description: r.Description,
			Category:    r.Category,
			Mitre:       r.Mitre,
			Severity:    r.Severity,
		})
	}
	if len(pack.Rules) == 0 {
		return model.RulePack{}, &ingestExitCode{code: 1, msg: "no rules generated from sources with current filters"}
	}
	if err := rules.EnforceRuleQualityForSpecs(pack.Rules, "ingest-generated", cfg.ruleQualityMode, cfg.logger); err != nil {
		return model.RulePack{}, &ingestExitCode{code: 1, msg: fmt.Sprintf("ingested rule quality check failed: %v", err)}
	}
	return pack, nil
}

// RunIngest converts threat-intelligence content into an external rule pack.
func RunIngest(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int {
	cfg, err := parseIngestFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		var ie *ingestExitCode
		if errors.As(err, &ie) {
			if ie.msg != "" {
				fmt.Fprintf(stderr, "%s\n", ie.msg)
			}
			return ie.code
		}
		return 2
	}
	if cfg.logCloser != nil {
		defer func() {
			if cerr := cfg.logCloser.Close(); cerr != nil {
				fmt.Fprintf(stderr, "warning: close log file: %v\n", cerr)
			}
		}()
	}

	docs, err := loadIngestSources(ctx, &cfg, stderr)
	if err != nil {
		var ie *ingestExitCode
		if errors.As(err, &ie) {
			if ie.msg != "" {
				fmt.Fprintf(stderr, "%s\n", ie.msg)
			}
			return ie.code
		}
		return 1
	}

	pack, err := processIngestSources(cfg, docs, stderr)
	if err != nil {
		var ie *ingestExitCode
		if errors.As(err, &ie) {
			if ie.msg != "" {
				fmt.Fprintf(stderr, "%s\n", ie.msg)
			}
			return ie.code
		}
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}

	if err := WriteRulePack(cfg.outPath, pack); err != nil {
		fmt.Fprintf(stderr, "failed to write rule pack: %v\n", err)
		return 1
	}

	if cfg.generateTests {
		if err := writeTestStub(cfg.outPath, pack.Name); err != nil {
			fmt.Fprintf(stderr, "failed to write test stub: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "generated test stub: %s\n", testStubPath(cfg.outPath))
	}

	summary := SummarizeRuleSpecs(pack.Rules)
	cfg.logger.Infof("ingest completed sources=%d rules=%d output=%s", len(docs), len(pack.Rules), cfg.outPath)
	fmt.Fprintf(stdout, "generated rule pack: %s\n", cfg.outPath)
	fmt.Fprintf(stdout, "name: %s\n", pack.Name)
	fmt.Fprintf(stdout, "sources read: %d\n", len(docs))
	fmt.Fprintf(
		stdout,
		"rules: total=%d critical=%d high=%d medium=%d low=%d info=%d\n",
		len(pack.Rules),
		summary[string(model.SeverityCritical)],
		summary[string(model.SeverityHigh)],
		summary[string(model.SeverityMedium)],
		summary[string(model.SeverityLow)],
		summary[string(model.SeverityInfo)],
	)
	return 0
}

type ingestOptions struct {
	MaxRules             int
	MinSeverity          model.Severity
	IncludeCommandHeur   bool
	IncludeContextualIoc bool
	Name                 string
	Description          string
}

// buildIngestedRulePack derives rule specs and metadata from source documents.
func buildIngestedRulePack(
	docs []SourceDocument,
	inputSources []string,
	ecosystems map[string]struct{},
	opts ingestOptions,
) model.RulePack {
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = "ingested-threat-rules"
	}

	collector := NewGeneratedRuleCollector(opts.MaxRules, opts.MinSeverity)
	if opts.IncludeCommandHeur {
		for _, cmd := range suspiciousCommandPatterns {
			collector.AddRule(model.Rule{
				ID:          cmd.id,
				Title:       cmd.title,
				Description: cmd.description,
				Category:    "ingested-threat-intel",
				Mitre:       cmd.mitre,
				Severity:    cmd.severity,
				Pattern:     cmd.pattern,
				Target:      model.TargetContent,
			})
		}
	}

	for _, doc := range docs {
		if rows, ok := ParseAffectedPackagesCSV(doc.Content); ok {
			AddAffectedPackageExposureRules(collector, rows)
		}

		scanner := bufio.NewScanner(strings.NewReader(doc.Content))
		scanner.Buffer(make([]byte, 0, 128*1024), maxLineBytes)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			plain := StripMarkup(line)
			if plain == "" {
				continue
			}
			lower := strings.ToLower(line)
			lowerPlain := strings.ToLower(plain)
			risky := containsRiskKeyword(lower) || containsRiskKeyword(lowerPlain)
			strongRisk := containsStrongRiskKeyword(lower) || containsStrongRiskKeyword(lowerPlain)

			if _, ok := ecosystems["general"]; ok {
				if opts.IncludeContextualIoc {
					AddGeneralIOCLineRules(collector, plain, risky, strongRisk, doc.Source, lineNo)
				}
			}
			if _, ok := ecosystems["github-actions"]; ok {
				AddGitHubActionRules(collector, plain, risky)
			}
			if _, ok := ecosystems["pypi"]; ok {
				AddPyPIRules(collector, plain, lowerPlain, risky)
			}
			if _, ok := ecosystems["npm"]; ok {
				AddNpmRules(collector, plain, lowerPlain, risky)
			}
			if _, ok := ecosystems["go"]; ok {
				AddGoRules(collector, plain, lowerPlain, risky)
			}
			if _, ok := ecosystems["cargo"]; ok {
				AddCargoRules(collector, plain, lowerPlain, risky)
			}
			if _, ok := ecosystems["container"]; ok {
				AddContainerRules(collector, plain, lowerPlain, risky)
			}
			if _, ok := ecosystems["mcp"]; ok {
				AddMcpRules(collector, plain, lowerPlain, risky)
			}
			if _, ok := ecosystems["agent-skills"]; ok {
				AddAgentSkillRules(collector, plain, lowerPlain, risky)
			}
		}
	}

	rules := collector.Rules()
	specs := make([]model.RuleSpec, 0, len(rules))
	for _, rule := range rules {
		specs = append(specs, model.RuleSpec{
			ID:          rule.ID,
			Title:       rule.Title,
			Description: rule.Description,
			Category:    rule.Category,
			Mitre:       rule.Mitre,
			Severity:    rule.Severity,
			Pattern:     rule.Pattern,
			Target:      rule.Target,
		})
	}

	return model.RulePack{
		Version:     1,
		Name:        name,
		Description: opts.Description,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Sources:     DedupeStrings(inputSources),
		Ecosystems:  model.SortedMapKeys(ecosystems),
		Rules:       specs,
	}
}

// GeneratedRuleCollector accumulates generated rules during ingest, enforcing per-family deduplication, severity floor, and max-rules cap.
type GeneratedRuleCollector struct {
	maxRules    int
	minSeverity model.Severity
	nextByFam   map[string]int
	seen        map[string]struct{}
	collected   []model.Rule
}

// NewGeneratedRuleCollector initializes de-dup aware generated-rule buffering.
func NewGeneratedRuleCollector(maxRules int, minSeverity model.Severity) *GeneratedRuleCollector {
	return &GeneratedRuleCollector{
		maxRules:    maxRules,
		minSeverity: minSeverity,
		nextByFam:   make(map[string]int, 16),
		seen:        make(map[string]struct{}, maxRules*2),
		collected:   make([]model.Rule, 0, maxRules),
	}
}

// AddRule inserts a generated rule, enforcing minimum severity, deduplication, and max-rules cap.
func (c *GeneratedRuleCollector) AddRule(rule model.Rule) {
	if len(c.collected) >= c.maxRules {
		return
	}
	if model.SeverityWeight(rule.Severity) < model.SeverityWeight(c.minSeverity) {
		return
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return
	}
	key := strings.ToLower(strings.TrimSpace(rule.Category)) + "|" + strings.TrimSpace(rule.Pattern)
	if _, exists := c.seen[key]; exists {
		return
	}
	c.seen[key] = struct{}{}

	if strings.TrimSpace(rule.ID) == "" {
		family := familyFromCategory(rule.Category)
		c.nextByFam[family]++
		rule.ID = fmt.Sprintf("INGEST-%s-%03d", family, c.nextByFam[family])
	}
	if strings.TrimSpace(rule.Title) == "" {
		rule.Title = "Ingested threat intelligence indicator"
	}
	if strings.TrimSpace(rule.Description) == "" {
		rule.Description = "Auto-generated from threat intelligence ingestion source."
	}
	if rule.Target == "" {
		rule.Target = model.TargetContent
	}
	c.collected = append(c.collected, rule)
}

// Rules returns the collected generated rules in deterministic severity-then-ID order.
func (c *GeneratedRuleCollector) Rules() []model.Rule {
	out := slices.Clone(c.collected)
	sortFindingsLikeRules(out)
	return out
}

// sortFindingsLikeRules keeps generated rules in deterministic output order.
func sortFindingsLikeRules(rules []model.Rule) {
	slices.SortFunc(rules, func(a, b model.Rule) int {
		if model.SeverityWeight(a.Severity) != model.SeverityWeight(b.Severity) {
			return model.SeverityWeight(b.Severity) - model.SeverityWeight(a.Severity)
		}
		return strings.Compare(a.ID, b.ID)
	})
}

// familyFromCategory maps categories into high-level summary buckets.
func familyFromCategory(category string) string {
	cat := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(category), "-", "_"))
	if cat == "" {
		return "GEN"
	}
	if len(cat) > 10 {
		cat = cat[:10]
	}
	return cat
}

// WriteRulePack persists generated rules to disk in canonical JSON form.
func WriteRulePack(outPath string, pack model.RulePack) error {
	outPath = strings.TrimSpace(outPath)
	if outPath == "" {
		return errors.New("empty output path")
	}
	abs, err := filepath.Abs(model.ExpandHomePath(outPath))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(abs, data, 0o644)
}

// SummarizeRuleSpecs aggregates generated rule counts by category family.
func SummarizeRuleSpecs(specs []model.RuleSpec) map[string]int {
	out := map[string]int{
		string(model.SeverityCritical): 0,
		string(model.SeverityHigh):     0,
		string(model.SeverityMedium):   0,
		string(model.SeverityLow):      0,
		string(model.SeverityInfo):     0,
	}
	for _, spec := range specs {
		out[string(spec.Severity)]++
	}
	return out
}

// DedupeStrings preserves insertion order while removing duplicates.
func DedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, item := range in {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

func testStubPath(outPath string) string {
	dir := filepath.Dir(outPath)
	base := filepath.Base(outPath)
	name := strings.TrimSuffix(base, ".json")
	name = strings.TrimPrefix(name, "rules.")
	return filepath.Join(dir, "rules.test."+name+".json")
}

func writeTestStub(outPath string, packName string) error {
	tp := model.RuleTestPack{
		Version:   1,
		Name:      packName + "-tests",
		RulesFile: filepath.Base(outPath),
		Tests:     []model.RuleTestCase{},
	}
	data, err := json.MarshalIndent(tp, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(testStubPath(outPath), data, 0o644)
}

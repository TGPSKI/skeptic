package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	configpkg "github.com/TGPSKI/skeptic/internal/config"
	"github.com/TGPSKI/skeptic/internal/corpus"
	"github.com/TGPSKI/skeptic/internal/model"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
)

func runCorpusGlobal(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: skeptic corpus <init|fetch|info|scan|purge|SHA action> [flags]\n  artifact actions: show, metadata, expected-rules")
		return 2
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	switch sub {
	case "init":
		return runCorpusInit(args[1:], stdout, stderr, gf)
	case "fetch":
		return runCorpusFetch(args[1:], stdout, stderr, gf)
	case "info":
		return runCorpusInfo(args[1:], stdout, stderr, gf)
	case "scan":
		return runCorpusScan(args[1:], stdout, stderr, gf)
	case "purge":
		return runCorpusPurge(args[1:], stdout, stderr, gf)
	default:
		if looksLikeHexPrefix(sub) {
			return runCorpusArtifact(sub, args[1:], stdout, stderr, gf)
		}
		fmt.Fprintf(stderr, "unknown corpus subcommand: %s\n", sub)
		return 2
	}
}

func looksLikeHexPrefix(s string) bool {
	if len(s) < 4 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && len(s)%2 == 0
}

func runCorpusArtifact(shaPrefix string, args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	if len(args) > 0 {
		action := strings.ToLower(strings.TrimSpace(args[0]))
		switch action {
		case "show":
			return runCorpusArtifactShow(shaPrefix, args[1:], stdout, stderr, gf)
		case "metadata":
			return runCorpusArtifactMetadata(shaPrefix, args[1:], stdout, stderr, gf)
		case "expected-rules":
			return runCorpusArtifactExpectedRules(shaPrefix, args[1:], stdout, stderr, gf)
		}
		if !strings.HasPrefix(action, "-") {
			fmt.Fprintf(stderr, "unknown artifact action: %s\nusage: skeptic corpus <SHA> [show|metadata|expected-rules] [flags]\n", action)
			return 2
		}
	}
	return runCorpusArtifactInfo(shaPrefix, args, stdout, stderr, gf)
}

func runCorpusArtifactInfo(shaPrefix string, args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus <SHA>", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
		}, nil)
	}
	var (
		pathFlag string
		showSHA  bool
	)
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	fs.BoolVar(&showSHA, "sha", false, "show full SHA256 hashes")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	config := loadCorpusConfig(gf.Config)
	c, err := corpus.Open(pathFlag, config)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	a := c.FindArtifactByPrefix(shaPrefix)
	if a == nil {
		fmt.Fprintf(stderr, "error: no unique artifact matching prefix %q\n", shaPrefix)
		return 1
	}
	return corpusInfoText(stdout, c, []corpus.Artifact{*a}, 1, 0, 0, showSHA)
}

func runCorpusArtifactShow(shaPrefix string, args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus <SHA> show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
			"r": "rules-dir",
			"f": "format",
		}, nil)
	}
	var (
		pathFlag string
		rulesDir string
		verbose  bool
		format   string
	)
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	fs.StringVar(&rulesDir, "rules-dir", "", "external rules directory")
	fs.StringVar(&rulesDir, "r", "", "external rules directory")
	fs.BoolVar(&verbose, "verbose", gf.Verbosity > 0, "verbose scan output")
	fs.StringVar(&format, "format", "text", "output format: text|json")
	fs.StringVar(&format, "f", "text", "output format: text|json")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if format != "text" && format != "json" {
		fmt.Fprintf(stderr, "invalid --format value: %q (use text or json)\n", format)
		return 2
	}

	config := loadCorpusConfig(gf.Config)

	c, err := corpus.Open(pathFlag, config)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	a := c.FindArtifactByPrefix(shaPrefix)
	if a == nil {
		fmt.Fprintf(stderr, "error: no unique artifact matching prefix %q\n", shaPrefix)
		return 1
	}

	result, err := corpus.ScanCorpus(context.Background(), corpus.ScanOptions{
		CorpusPath:     pathFlag,
		ConfigValues:   config,
		RulesDir:       rulesDir,
		Verbose:        verbose,
		Stderr:         stderr,
		ArtifactFilter: shaPrefix,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	findings := result.Report.Findings
	scanpkg.SortFindings(findings)

	fmt.Fprintf(stdout, "%s  %s  (%s)\n", a.ID[:12], a.OriginalName, a.SourceType)
	fmt.Fprintf(stdout, "%d findings\n\n", len(findings))

	if format == "json" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(findings); err != nil {
			fmt.Fprintf(stderr, "error: encode json: %v\n", err)
			return 1
		}
		return 0
	}

	for _, f := range findings {
		sev := strings.ToUpper(string(f.Severity))
		lineRef := ""
		if f.Line > 0 {
			lineRef = fmt.Sprintf(":%d", f.Line)
		}
		fmt.Fprintf(stdout, "  [%s] %s  %s%s\n", sev, f.RuleID, a.OriginalName, lineRef)
		if f.Match != "" {
			fmt.Fprintf(stdout, "    match: %s\n", f.Match)
		}
		if f.Title != "" {
			fmt.Fprintf(stdout, "    title: %s\n", f.Title)
		}
		if f.ConfidenceClass != "" {
			fmt.Fprintf(stdout, "    confidence: %s\n", f.ConfidenceClass)
		}
	}

	if len(result.Deltas) > 0 {
		for _, d := range result.Deltas {
			if len(d.Missing) > 0 {
				fmt.Fprintf(stdout, "\n  missing expected rules: %s\n", strings.Join(d.Missing, ", "))
			}
			if len(d.Unexpected) > 0 {
				fmt.Fprintf(stdout, "\n  unexpected rules: %s\n", strings.Join(d.Unexpected, ", "))
			}
		}
	}
	return 0
}

func runCorpusArtifactMetadata(shaPrefix string, args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus <SHA> metadata", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
		}, nil)
	}
	var pathFlag string
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(stderr, "error: metadata value is required")
		fmt.Fprintln(stderr, "usage: skeptic corpus <SHA> metadata <string>")
		fmt.Fprintln(stderr, "  value can be plain text, JSON, or YAML")
		return 2
	}
	entry := strings.Join(remaining, " ")

	config := loadCorpusConfig(gf.Config)
	c, err := corpus.Open(pathFlag, config)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := c.AppendMetadata(shaPrefix, entry); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	a := c.FindArtifactByPrefix(shaPrefix)
	if a != nil {
		fmt.Fprintf(stdout, "%s: metadata appended (%d entries)\n", a.ID[:12], len(a.Metadata))
	}
	return 0
}

func runCorpusArtifactExpectedRules(shaPrefix string, args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus <SHA> expected-rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
		}, nil)
	}
	var pathFlag string
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(stderr, "error: comma-separated rule IDs required")
		fmt.Fprintln(stderr, "usage: skeptic corpus <SHA> expected-rules <RULE-1,RULE-2,...>")
		fmt.Fprintln(stderr, "  pass \"none\" to clear expected rules")
		return 2
	}
	raw := strings.Join(remaining, ",")

	var rules []string
	if raw != "none" {
		for _, r := range strings.Split(raw, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				rules = append(rules, r)
			}
		}
	}

	config := loadCorpusConfig(gf.Config)
	c, err := corpus.Open(pathFlag, config)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if err := c.SetExpectedRules(shaPrefix, rules); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	a := c.FindArtifactByPrefix(shaPrefix)
	if a != nil {
		if len(rules) == 0 {
			fmt.Fprintf(stdout, "%s: expected rules cleared\n", a.ID[:12])
		} else {
			fmt.Fprintf(stdout, "%s: expected rules set (%d): %s\n", a.ID[:12], len(rules), strings.Join(rules, ", "))
		}
	}
	return 0
}

func loadCorpusConfig(configPath string) map[string]string {
	values, _, err := configpkg.LoadConfigValues(configPath)
	if err != nil {
		return nil
	}
	return values
}

func runCorpusInit(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
		}, nil)
	}
	var pathFlag string
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	config := loadCorpusConfig(gf.Config)
	resolved, err := corpus.Init(pathFlag, config, nil, nil)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "corpus initialized: %s\n", resolved)
	return 0
}

func runCorpusFetch(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus fetch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
			"s": "source",
			"a": "allow-host",
			"e": "expected-rules",
			"m": "max-corpus-bytes",
		}, nil)
	}
	var (
		pathFlag      string
		source        string
		allowHostsRaw string
		allowHTTP     bool
		expectedRules string
		maxBytes      int64
		metadataRaw   string
	)
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	fs.StringVar(&source, "source", "", "url or local file path to fetch")
	fs.StringVar(&source, "s", "", "url or local file path to fetch")
	fs.StringVar(&allowHostsRaw, "allow-host", "", "comma-separated allowed hostnames for URL fetch")
	fs.StringVar(&allowHostsRaw, "a", "", "comma-separated allowed hostnames")
	fs.BoolVar(&allowHTTP, "allow-http", false, "allow plain HTTP URLs")
	fs.StringVar(&expectedRules, "expected-rules", "", "comma-separated rule IDs expected to fire")
	fs.StringVar(&expectedRules, "e", "", "comma-separated expected rule IDs")
	fs.Int64Var(&maxBytes, "max-corpus-bytes", 0, "max total corpus size in bytes (default 50MB)")
	fs.Int64Var(&maxBytes, "m", 0, "max total corpus size in bytes")
	fs.StringVar(&metadataRaw, "metadata", "", "metadata to attach (text, JSON, or YAML)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if source == "" {
		fmt.Fprintln(stderr, "error: --source / -s is required")
		return 2
	}

	config := loadCorpusConfig(gf.Config)
	c, err := corpus.Open(pathFlag, config)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	allowedHosts := make(map[string]struct{})
	if allowHostsRaw != "" {
		for _, h := range strings.Split(allowHostsRaw, ",") {
			h = strings.ToLower(strings.TrimSpace(h))
			if h != "" {
				allowedHosts[h] = struct{}{}
			}
		}
	}

	var rules []string
	if expectedRules != "" {
		for _, r := range strings.Split(expectedRules, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				rules = append(rules, r)
			}
		}
	}

	var metadata []string
	if metadataRaw != "" {
		metadata = append(metadata, metadataRaw)
	}

	opts := corpus.FetchOptions{
		AllowedHosts:  allowedHosts,
		AllowHTTP:     allowHTTP,
		ExpectedRules: rules,
		MaxBytes:      maxBytes,
		Metadata:      metadata,
	}

	if err := c.Fetch(context.Background(), source, opts); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "fetched: %s\n", source)
	return 0
}

func runCorpusInfo(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus info", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
			"f": "format",
			"l": "limit",
		}, nil)
	}
	var (
		pathFlag   string
		showSHA    bool
		format     string
		sortKey    string
		filterType string
		filterName string
		filterRule string
		filterSrc  string
		limit      int
		offset     int
	)
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	fs.BoolVar(&showSHA, "sha", false, "show full SHA256 hashes")
	fs.StringVar(&format, "format", "text", "output format: text|json")
	fs.StringVar(&format, "f", "text", "output format: text|json")
	fs.StringVar(&sortKey, "sort", "date", "sort key: name|size|date|source-type (prefix - for descending)")
	fs.StringVar(&filterType, "source-type", "", "filter by source type (case-insensitive exact match)")
	fs.StringVar(&filterName, "name", "", "filter by artifact name (case-insensitive substring)")
	fs.StringVar(&filterRule, "rule", "", "filter by expected rule ID (case-insensitive substring)")
	fs.StringVar(&filterSrc, "source", "", "filter by source URL/path (case-insensitive substring)")
	fs.IntVar(&limit, "limit", 0, "max artifacts to show (0 = all)")
	fs.IntVar(&limit, "l", 0, "max artifacts to show")
	fs.IntVar(&offset, "offset", 0, "skip first N artifacts")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if format != "text" && format != "json" {
		fmt.Fprintf(stderr, "invalid --format value: %q (use text or json)\n", format)
		return 2
	}

	config := loadCorpusConfig(gf.Config)
	c, err := corpus.Open(pathFlag, config)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	artifacts := corpus.FilterArtifacts(c.Manifest.Artifacts, corpus.ArtifactFilter{
		SourceType: filterType,
		Name:       filterName,
		Rule:       filterRule,
		Source:     filterSrc,
	})
	corpus.SortArtifacts(artifacts, sortKey)
	total := len(artifacts)
	artifacts = corpus.Paginate(artifacts, offset, limit)

	if format == "json" {
		return corpusInfoJSON(stdout, stderr, c, artifacts, total, offset)
	}
	return corpusInfoText(stdout, c, artifacts, total, offset, limit, showSHA)
}

func corpusInfoJSON(stdout io.Writer, stderr io.Writer, c *corpus.Corpus, artifacts []corpus.Artifact, total, offset int) int {
	type jsonOut struct {
		Root      string            `json:"root"`
		Total     int               `json:"total"`
		Matched   int               `json:"matched"`
		Showing   int               `json:"showing"`
		Offset    int               `json:"offset"`
		Artifacts []corpus.Artifact `json:"artifacts"`
	}
	out := jsonOut{
		Root:      c.Root,
		Total:     len(c.Manifest.Artifacts),
		Matched:   total,
		Showing:   len(artifacts),
		Offset:    offset,
		Artifacts: artifacts,
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(stderr, "error: encode json: %v\n", err)
		return 1
	}
	return 0
}

func corpusInfoText(stdout io.Writer, c *corpus.Corpus, artifacts []corpus.Artifact, total, offset, limit int, showSHA bool) int {
	fmt.Fprint(stdout, c.Info())
	if total != len(c.Manifest.Artifacts) {
		fmt.Fprintf(stdout, "Matched: %d of %d\n", total, len(c.Manifest.Artifacts))
	}
	if offset > 0 || (limit > 0 && limit < total) {
		showing := len(artifacts)
		fmt.Fprintf(stdout, "Showing: %d (offset %d)\n", showing, offset)
	}
	for _, a := range artifacts {
		idDisplay := a.ID[:12]
		if showSHA {
			idDisplay = a.ID
		}
		fmt.Fprintf(stdout, "\n  %s  %s  (%s)\n", idDisplay, a.OriginalName, a.SourceType)
		fmt.Fprintf(stdout, "    source: %s\n", a.Source)
		fmt.Fprintf(stdout, "    size: %d bytes  fetched: %s\n", a.SizeBytes, a.FetchTime)
		if showSHA {
			fmt.Fprintf(stdout, "    plaintext-sha256:  %s\n", a.PlaintextSHA256)
			fmt.Fprintf(stdout, "    encrypted-sha256:  %s\n", a.EncryptedSHA256)
		}
		if len(a.ExpectedRules) > 0 {
			fmt.Fprintf(stdout, "    expected: %s\n", strings.Join(a.ExpectedRules, ", "))
		}
		if len(a.Metadata) > 0 {
			fmt.Fprintf(stdout, "    metadata:\n")
			for _, m := range a.Metadata {
				fmt.Fprintf(stdout, "      - %s\n", m)
			}
		}
	}
	return 0
}

//nolint:gocyclo // CLI subcommand with flag parsing, validation, scan orchestration, and output routing
func runCorpusScan(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
			"f": "format",
			"o": "out",
			"r": "rules-dir",
			"t": "corpus-timeout",
		}, nil)
	}
	var (
		pathFlag    string
		format      string
		outPath     string
		rulesDir    string
		failOn      string
		timeout     int
		noRulepacks bool
		learn       bool
	)
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	fs.StringVar(&format, "format", "text", "output format: json|text|sarif|markdown")
	fs.StringVar(&format, "f", "text", "output format: json|text|sarif|markdown")
	fs.StringVar(&outPath, "out", "", "write output to file")
	fs.StringVar(&outPath, "o", "", "write output to file")
	fs.StringVar(&rulesDir, "rules-dir", "", "additional rules directory")
	fs.StringVar(&rulesDir, "r", "", "additional rules directory")
	fs.StringVar(&failOn, "fail-on", "", "fail threshold: none|info|low|medium|high|critical")
	fs.IntVar(&timeout, "corpus-timeout", 60, "scan timeout in seconds (per artifact)")
	fs.IntVar(&timeout, "t", 60, "scan timeout in seconds")
	fs.BoolVar(&noRulepacks, "no-rulepacks", false, "skip auto-loading rulepacks/campaigns/")
	fs.BoolVar(&learn, "learn", false, "auto-append detected rule IDs to each artifact's expected_rules")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if _, err := parseOutputFormat(format); err != nil {
		fmt.Fprintf(stderr, "invalid --format value: %v\n", err)
		return 2
	}
	if failOn != "" {
		if _, err := model.ParseSeverity(failOn); err != nil {
			fmt.Fprintf(stderr, "invalid --fail-on value: %v\n", err)
			return 2
		}
	}

	stopProfile, profErr := globalProfileAndStop(gf, stderr)
	if profErr != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", profErr)
		return 1
	}
	defer stopProfile()

	var artifactFilter string
	if positional := fs.Args(); len(positional) > 0 {
		artifactFilter = positional[0]
	}

	config := loadCorpusConfig(gf.Config)
	if !noRulepacks {
		sys, _, _ := configpkg.LoadSystemConfig("")
		if sys.CorpusNoRulepacks {
			noRulepacks = true
		}
	}
	opts := corpus.ScanOptions{
		CorpusPath:     pathFlag,
		ConfigValues:   config,
		Format:         format,
		OutPath:        outPath,
		RulesDir:       rulesDir,
		FailOn:         failOn,
		Timeout:        timeout,
		Verbose:        gf.Verbosity > 0 && !gf.Quiet,
		Stderr:         stderr,
		ArtifactFilter: artifactFilter,
		NoRulepacks:    noRulepacks,
		Learn:          learn,
	}

	ctx := context.Background()
	result, err := corpus.ScanCorpus(ctx, opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	outputFormat, _ := parseOutputFormat(format)

	reportDest := stdout
	var outFile *os.File
	closeOutFile := true
	if outPath != "" {
		f, fErr := os.Create(outPath)
		if fErr != nil {
			fmt.Fprintf(stderr, "error: create output file: %v\n", fErr)
			return 1
		}
		defer func() {
			if closeOutFile {
				if cerr := f.Close(); cerr != nil {
					fmt.Fprintf(stderr, "warning: close output file: %v\n", cerr)
				}
			}
		}()
		outFile = f
		reportDest = f
	}

	scanpkg.SortFindings(result.Report.Findings)
	result.Report.FindingsBySeverity = scanpkg.SummarizeFindings(result.Report.Findings)
	if _, code := emitReport(reportDest, stderr, result.Report, outputFormat); code != 0 {
		return code
	}

	if outFile != nil {
		closeOutFile = false
		if err := outFile.Close(); err != nil {
			fmt.Fprintf(stderr, "error: close output file: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "scanned %d files, %d findings\n",
			result.Report.ScannedFiles, len(result.Report.Findings))
		fmt.Fprintf(stdout, "wrote %s report to %s\n", format, outPath)
	}

	if len(result.Deltas) > 0 {
		fmt.Fprintln(stdout, "\nexpected-rules delta:")
		for _, d := range result.Deltas {
			fmt.Fprintf(stdout, "  %s (%s):\n", d.ArtifactID[:12], d.OriginalName)
			if len(d.Missing) > 0 {
				fmt.Fprintf(stdout, "    MISSING: %s\n", strings.Join(d.Missing, ", "))
			}
			if len(d.Unexpected) > 0 {
				fmt.Fprintf(stdout, "    EXTRA:   %s\n", strings.Join(d.Unexpected, ", "))
			}
			if len(d.Missing) == 0 && len(d.Unexpected) == 0 {
				fmt.Fprintln(stdout, "    OK")
			}
		}
	}

	if failOn != "" {
		failSev, _ := model.ParseSeverity(failOn)
		if failSev != model.SeverityNone && scanpkg.ThresholdExceeded(result.Report.Findings, failSev, "") {
			return 3
		}
	}

	for _, d := range result.Deltas {
		if len(d.Missing) > 0 {
			return 1
		}
	}
	return 0
}

func runCorpusPurge(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	fs := flag.NewFlagSet("skeptic corpus purge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path",
			"y": "confirm",
		}, nil)
	}
	var (
		pathFlag string
		confirm  bool
	)
	fs.StringVar(&pathFlag, "path", "", "corpus directory path")
	fs.StringVar(&pathFlag, "p", "", "corpus directory path")
	fs.BoolVar(&confirm, "confirm", false, "confirm deletion of corpus data")
	fs.BoolVar(&confirm, "y", false, "confirm deletion")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	config := loadCorpusConfig(gf.Config)
	if err := corpus.Purge(pathFlag, config, confirm); err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		if !confirm {
			return 2
		}
		return 1
	}
	fmt.Fprintln(stdout, "corpus purged")
	return 0
}

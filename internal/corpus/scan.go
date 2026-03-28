package corpus

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/rules"
	"github.com/TGPSKI/skeptic/internal/scan"
)

// ScanFunc is the signature for the scan engine entry point.
type ScanFunc func(ctx context.Context, rules []model.Rule, opts model.ScanOptions) (model.Report, error)

// ScanResult holds the scan report plus per-artifact detection deltas.
type ScanResult struct {
	Report model.Report
	Deltas []ArtifactDelta
}

// ArtifactDelta tracks expected vs actual rule detections for one artifact.
type ArtifactDelta struct {
	ArtifactID   string
	OriginalName string
	Expected     []string
	Detected     []string
	Missing      []string
	Unexpected   []string
}

// ScanOptions configures a corpus scan.
type ScanOptions struct {
	CorpusPath     string
	ConfigValues   map[string]string
	Format         string
	OutPath        string
	RulesDir       string
	FailOn         string
	Timeout        int
	Verbose        bool
	Stderr         io.Writer
	ArtifactFilter string // SHA prefix to scan a single artifact; empty = all
	NoRulepacks    bool   // skip auto-loading rulepacks/campaigns/
	Learn          bool   // auto-append newly detected rule IDs to each artifact's expected_rules
}

// ScanCorpus decrypts artifacts to namespaced temp dirs, scans with isolated options, and reports results.
func ScanCorpus(ctx context.Context, opts ScanOptions) (ScanResult, error) {
	logf := func(format string, args ...any) {}
	if opts.Verbose && opts.Stderr != nil {
		logf = func(format string, args ...any) {
			fmt.Fprintf(opts.Stderr, "[corpus] "+format+"\n", args...)
		}
	}

	c, err := Open(opts.CorpusPath, opts.ConfigValues)
	if err != nil {
		return ScanResult{}, err
	}
	logf("opened corpus at %s", c.Root)
	logf("loaded manifest: %d artifacts, %d bytes total", len(c.Manifest.Artifacts), c.Manifest.TotalSizeBytes())

	artifacts := c.Manifest.Artifacts
	if opts.ArtifactFilter != "" {
		a := c.FindArtifactByPrefix(opts.ArtifactFilter)
		if a == nil {
			return ScanResult{}, fmt.Errorf("corpus: no unique artifact matching prefix %q", opts.ArtifactFilter)
		}
		artifacts = []Artifact{*a}
		logf("filtered to single artifact: %s (%s)", a.ID[:12], a.OriginalName)
	}
	if len(artifacts) == 0 {
		return ScanResult{}, fmt.Errorf("corpus: no artifacts to scan")
	}

	tmpRoot, err := os.MkdirTemp("", "skeptic-corpus-scan-")
	if err != nil {
		return ScanResult{}, fmt.Errorf("corpus: create temp dir: %w", err)
	}
	if err := os.Chmod(tmpRoot, 0700); err != nil {
		os.RemoveAll(tmpRoot) //nolint:errcheck // best-effort cleanup
		return ScanResult{}, fmt.Errorf("corpus: chmod temp dir: %w", err)
	}
	logf("created temp dir: %s (mode 0700)", tmpRoot)
	defer func() {
		logf("secure-wiping temp dir: %s", tmpRoot)
		secureWipe(tmpRoot)
		logf("temp dir wiped")
	}()

	artifactMap := make(map[string]Artifact)
	for i, a := range artifacts {
		logf("decrypt [%d/%d] %s (%s, %d bytes, enc-hash %s)",
			i+1, len(artifacts), a.OriginalName, a.ID[:12], a.SizeBytes, a.EncryptedSHA256[:12])
		plaintext, err := c.DecryptArtifact(a)
		if err != nil {
			return ScanResult{}, err
		}
		logf("  decrypted OK, plaintext %d bytes", len(plaintext))

		artDir := filepath.Join(tmpRoot, a.ID)
		if err := os.MkdirAll(artDir, 0700); err != nil {
			return ScanResult{}, fmt.Errorf("corpus: create artifact dir: %w", err)
		}
		outPath := filepath.Join(artDir, a.OriginalName)
		if err := os.WriteFile(outPath, plaintext, 0600); err != nil {
			return ScanResult{}, fmt.Errorf("corpus: write decrypted artifact: %w", err)
		}
		logf("  wrote %s", outPath)
		artifactMap[a.ID] = a
	}

	rulesDir := opts.RulesDir
	if rulesDir == "" && !opts.NoRulepacks {
		candidate := "rulepacks/campaigns"
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			rulesDir = candidate
			logf("auto-discovered rulepacks at %s", candidate)
		}
	}

	scanRules, err := rules.BuildRuleSet(
		true, rules.DefaultRules(),
		"", rulesDir,
		"", "", false,
		model.RuleQualityWarn,
		logging.NewLogger(logging.LogError, io.Discard),
	)
	if err != nil {
		return ScanResult{}, fmt.Errorf("corpus: build ruleset: %w", err)
	}
	logf("loaded %d rules (built-in + rulepacks)", len(scanRules))

	logLevel := logging.LogError
	logDest := io.Writer(io.Discard)
	if opts.Verbose && opts.Stderr != nil {
		logLevel = logging.LogInfo
		logDest = opts.Stderr
	}

	scanOpts := model.ScanOptions{
		Paths:              []string{tmpRoot},
		Profile:            model.ProfileRepo,
		ScanStyle:          model.ScanStyleHybrid,
		ThreatMode:         model.ThreatModeAll,
		Mode:               model.ScanModeIR,
		PolicyChecks:       false,
		MaxBytes:           scan.DefaultMaxBytes,
		FailOn:             model.SeverityNone,
		Workers:            2,
		MaxFindings:        10000,
		MaxFindingsPerFile: 500,
		RedactSecrets:      true,
		Incremental:        false,
		Logger:             logging.NewLogger(logLevel, logDest),
	}

	logf("scanning %s (mode=ir, style=hybrid, threat-mode=all, %d rules)", tmpRoot, len(scanRules))
	report, err := scan.ScanWithOptions(ctx, scanRules, scanOpts)
	if err != nil {
		return ScanResult{}, fmt.Errorf("corpus: scan: %w", err)
	}
	logf("scan complete: %d files scanned, %d findings", report.ScannedFiles, len(report.Findings))

	report.TargetPath = c.Root
	report.TargetPaths = []string{c.Root}

	deltas := computeDeltas(report, artifactMap, tmpRoot)
	if len(deltas) > 0 {
		logf("computed deltas for %d artifacts with expected rules", len(deltas))
	}

	if opts.Learn {
		learned := learnExpectedRules(c, report, artifactMap, tmpRoot, logf)
		if learned > 0 {
			deltas = computeDeltas(report, artifactMap, tmpRoot)
		}
	}

	return ScanResult{Report: report, Deltas: deltas}, nil
}

// learnExpectedRules appends newly detected rule IDs to each artifact's
// expected_rules and persists the manifest. Returns the number of artifacts updated.
func learnExpectedRules(c *Corpus, report model.Report, artifacts map[string]Artifact, tmpRoot string, logf func(string, ...any)) int {
	findingsByArtifact := groupFindingsByArtifact(report, tmpRoot)

	updated := 0
	for id := range artifacts {
		detected := findingsByArtifact[id]
		if len(detected) == 0 {
			continue
		}

		a := c.FindArtifactByPrefix(id)
		if a == nil {
			continue
		}

		existing := make(map[string]struct{}, len(a.ExpectedRules))
		for _, r := range a.ExpectedRules {
			existing[r] = struct{}{}
		}

		var added []string
		for r := range detected {
			if _, ok := existing[r]; !ok {
				a.ExpectedRules = append(a.ExpectedRules, r)
				added = append(added, r)
			}
		}
		if len(added) > 0 {
			// Update the local map so delta recomputation sees the new rules
			artifacts[id] = *a
			updated++
			logf("learn: %s +%d rules (%s)", id[:12], len(added), strings.Join(added, ", "))
		}
	}

	if updated > 0 {
		if err := WriteManifest(filepath.Join(c.Root, corpusManifest), c.Manifest); err != nil {
			logf("learn: failed to write manifest: %v", err)
			return 0
		}
		logf("learn: updated %d artifacts, manifest saved", updated)
	}
	return updated
}

// groupFindingsByArtifact maps artifact ID → set of detected rule IDs.
// Handles both absolute paths (filepath.Join(tmpRoot, id, name)) and
// relative paths already produced by the scan engine (id/name).
func groupFindingsByArtifact(report model.Report, tmpRoot string) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})
	for _, f := range report.Findings {
		filePath := f.File
		// Try filepath.Rel for absolute paths
		if filepath.IsAbs(filePath) {
			rel, err := filepath.Rel(tmpRoot, filePath)
			if err != nil {
				continue
			}
			filePath = rel
		}
		// Normalize to forward slashes then split on first separator
		filePath = filepath.ToSlash(filePath)
		parts := strings.SplitN(filePath, "/", 2)
		if len(parts) == 0 {
			continue
		}
		artID := parts[0]
		if _, ok := result[artID]; !ok {
			result[artID] = make(map[string]struct{})
		}
		result[artID][f.RuleID] = struct{}{}
	}
	return result
}

func computeDeltas(report model.Report, artifacts map[string]Artifact, tmpRoot string) []ArtifactDelta {
	findingsByArtifact := groupFindingsByArtifact(report, tmpRoot)

	var deltas []ArtifactDelta
	for id, a := range artifacts {
		if len(a.ExpectedRules) == 0 {
			continue
		}
		detected := findingsByArtifact[id]
		detectedList := make([]string, 0, len(detected))
		for r := range detected {
			detectedList = append(detectedList, r)
		}

		var missing, unexpected []string
		expectedSet := make(map[string]struct{}, len(a.ExpectedRules))
		for _, r := range a.ExpectedRules {
			expectedSet[r] = struct{}{}
			if _, ok := detected[r]; !ok {
				missing = append(missing, r)
			}
		}
		for r := range detected {
			if _, ok := expectedSet[r]; !ok {
				unexpected = append(unexpected, r)
			}
		}

		deltas = append(deltas, ArtifactDelta{
			ArtifactID:   id,
			OriginalName: a.OriginalName,
			Expected:     a.ExpectedRules,
			Detected:     detectedList,
			Missing:      missing,
			Unexpected:   unexpected,
		})
	}
	return deltas
}

func secureWipe(dir string) {
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		zeros := make([]byte, info.Size())
		os.WriteFile(path, zeros, 0600) //nolint:errcheck // best-effort secure wipe
		return nil
	})
	os.RemoveAll(dir) //nolint:errcheck // best-effort cleanup
}

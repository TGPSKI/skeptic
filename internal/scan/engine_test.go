package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

func TestScanWithOptionsCancellation(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 500; i++ {
		name := filepath.Join(root, fmt.Sprintf("f%d.txt", i))
		if err := os.WriteFile(name, []byte("safe content line\n"), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanWithOptions(ctx, nil, model.ScanOptions{
		Paths:    []string{root},
		Profile:  model.ProfileRepo,
		MaxBytes: DefaultMaxBytes,
		Workers:  2,
	})
	if err == nil {
		t.Fatal("expected error from canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestScanWithOptionsMidScanCancellation(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 2000; i++ {
		name := filepath.Join(root, fmt.Sprintf("file%04d.txt", i))
		if err := os.WriteFile(name, []byte("safe content line\n"), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}

	goroutinesBefore := runtime.NumGoroutine()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	_, err := ScanWithOptions(ctx, nil, model.ScanOptions{
		Paths:    []string{root},
		Profile:  model.ProfileRepo,
		MaxBytes: DefaultMaxBytes,
		Workers:  4,
	})
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context error or nil, got %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	goroutinesAfter := runtime.NumGoroutine()
	leaked := goroutinesAfter - goroutinesBefore
	if leaked > 2 {
		t.Fatalf("potential goroutine leak: before=%d after=%d leaked=%d", goroutinesBefore, goroutinesAfter, leaked)
	}
}

func testConcurrentScanRules(t *testing.T) []model.Rule {
	t.Helper()
	re := regexp.MustCompile(`xyzzy`)
	return []model.Rule{
		{
			ID: "TEST-XYZZY-001", Title: "marker", Description: "test",
			Category: "test", Mitre: "T0001", Severity: model.SeverityLow,
			Pattern: `xyzzy`, Target: model.TargetContent, RE: re,
			LiteralHint: "xyzzy",
		},
	}
}

func TestScanWithOptionsConcurrentCalls(t *testing.T) {
	root := t.TempDir()
	for i := range 10 {
		name := filepath.Join(root, fmt.Sprintf("f%d.txt", i))
		if err := os.WriteFile(name, []byte("line xyzzy\n"), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	rules := testConcurrentScanRules(t)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	reports := make([]model.Report, 4)
	for i := range 4 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rep, err := ScanWithOptions(context.Background(), rules, model.ScanOptions{
				Paths:              []string{root},
				Profile:            model.ProfileRepo,
				MaxBytes:           DefaultMaxBytes,
				Workers:            4,
				MaxFindings:        500,
				MaxFindingsPerFile: 100,
				ScanStyle:          model.ScanStylePattern,
				PolicyChecks:       false,
				Logger:             logging.NewLogger(logging.LogError, io.Discard),
			})
			reports[idx] = rep
			errs[idx] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d scan error: %v", i, err)
		}
		if reports[i].ScannedFiles != 10 {
			t.Fatalf("goroutine %d: ScannedFiles=%d want 10", i, reports[i].ScannedFiles)
		}
		if len(reports[i].Findings) < 10 {
			t.Fatalf("goroutine %d: expected findings per file, got %d", i, len(reports[i].Findings))
		}
	}
}

func TestScanMaxFilesEnforcement(t *testing.T) {
	root := t.TempDir()
	for i := range 50 {
		name := filepath.Join(root, fmt.Sprintf("n%d.txt", i))
		if err := os.WriteFile(name, []byte("a\n"), 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
	}
	rep, err := ScanWithOptions(context.Background(), nil, model.ScanOptions{
		Paths:        []string{root},
		Profile:      model.ProfileRepo,
		MaxBytes:     DefaultMaxBytes,
		Workers:      4,
		MaxFiles:     5,
		MaxFindings:  100,
		ScanStyle:    model.ScanStylePattern,
		PolicyChecks: false,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.ScannedFiles > 5 {
		t.Fatalf("ScannedFiles=%d want <=5", rep.ScannedFiles)
	}
	if !rep.MaxFilesReached {
		t.Fatal("expected MaxFilesReached=true")
	}
}

func TestScanMaxFindingsEnforcement(t *testing.T) {
	root := t.TempDir()
	var lines string
	for range 30 {
		lines += "xyzzy\n"
	}
	if err := os.WriteFile(filepath.Join(root, "many.txt"), []byte(lines), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	rules := testConcurrentScanRules(t)
	rep, err := ScanWithOptions(context.Background(), rules, model.ScanOptions{
		Paths:              []string{root},
		Profile:            model.ProfileRepo,
		MaxBytes:           DefaultMaxBytes,
		Workers:            2,
		MaxFindings:        3,
		MaxFindingsPerFile: 500,
		ScanStyle:          model.ScanStylePattern,
		PolicyChecks:       false,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rep.Findings) > 3 {
		t.Fatalf("len(Findings)=%d want <=3", len(rep.Findings))
	}
	if !rep.MaxFindingsReached {
		t.Fatal("expected MaxFindingsReached=true")
	}
}

func TestScanPermissionErrors(t *testing.T) {
	root := t.TempDir()
	readable := filepath.Join(root, "ok.txt")
	if err := os.WriteFile(readable, []byte("hello\n"), 0o644); err != nil {
		t.Fatalf("write ok file: %v", err)
	}
	locked := filepath.Join(root, "locked.txt")
	if err := os.WriteFile(locked, []byte("secret\n"), 0o644); err != nil {
		t.Fatalf("write locked file: %v", err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o644) })

	rep, err := ScanWithOptions(context.Background(), nil, model.ScanOptions{
		Paths:                  []string{root},
		Profile:                model.ProfileRepo,
		MaxBytes:               DefaultMaxBytes,
		Workers:                2,
		MaxFindings:            50,
		IgnorePermissionErrors: true,
		ScanStyle:              model.ScanStylePattern,
		PolicyChecks:           false,
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep.PermissionErrors == 0 {
		t.Skip("no permission errors observed (running as root or permissive environment)")
	}
}

func TestPolyglotBinaryThreshold(t *testing.T) {
	root := t.TempDir()

	t.Run("binary with 2 formats does not emit polyglot", func(t *testing.T) {
		data := make([]byte, 512)
		data[0] = 0x89
		data[1] = 'P'
		data[2] = 'N'
		data[3] = 'G'
		data[100] = 0x1f
		data[101] = 0x8b
		path := filepath.Join(root, "image.png")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		result := ScanSingleFile(path, root, nil, nil, ScanFileOptions{
			MaxBytes:           DefaultMaxBytes,
			MaxFindingsPerFile: 50,
			ScanStyle:          model.ScanStylePattern,
			ThreatMode:         model.ThreatModeAll,
		})
		for _, f := range result.Findings {
			if f.RuleID == "ENC-POLYGLOT-001" {
				t.Fatalf("binary with 2 formats (PNG+gzip) should not emit polyglot, got: %s", f.Match)
			}
		}
	})

	t.Run("binary with 3 formats emits polyglot", func(t *testing.T) {
		data := make([]byte, 512)
		data[0] = 0x89
		data[1] = 'P'
		data[2] = 'N'
		data[3] = 'G'
		data[100] = 0x1f
		data[101] = 0x8b
		data[200] = 0x50
		data[201] = 0x4B
		data[202] = 0x03
		data[203] = 0x04
		path := filepath.Join(root, "suspicious.png")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		result := ScanSingleFile(path, root, nil, nil, ScanFileOptions{
			MaxBytes:           DefaultMaxBytes,
			MaxFindingsPerFile: 50,
			ScanStyle:          model.ScanStylePattern,
			ThreatMode:         model.ThreatModeAll,
		})
		found := false
		for _, f := range result.Findings {
			if f.RuleID == "ENC-POLYGLOT-001" {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("binary with 3+ formats (PNG+gzip+ZIP) should emit polyglot findings")
		}
	})

	t.Run("text with any polyglot sig emits finding", func(t *testing.T) {
		text := []byte("This is a normal text file with some content\n")
		text = append(text, 0x50, 0x4B, 0x03, 0x04)
		text = append(text, []byte("\nmore text here\n")...)
		path := filepath.Join(root, "readme.txt")
		if err := os.WriteFile(path, text, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		result := ScanSingleFile(path, root, nil, nil, ScanFileOptions{
			MaxBytes:           DefaultMaxBytes,
			MaxFindingsPerFile: 50,
			ScanStyle:          model.ScanStylePattern,
			ThreatMode:         model.ThreatModeAll,
		})
		found := false
		for _, f := range result.Findings {
			if f.RuleID == "ENC-POLYGLOT-001" {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("text file with embedded ZIP signature should emit polyglot finding")
		}
	})
}

func TestScanCorruptIncrementalCache(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("xyzzy\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	cachePath := filepath.Join(root, ".skeptic-state.json")
	if err := os.WriteFile(cachePath, []byte("{not valid json"), 0o644); err != nil {
		t.Fatalf("write corrupt cache: %v", err)
	}
	rules := testConcurrentScanRules(t)
	rep, err := ScanWithOptions(context.Background(), rules, model.ScanOptions{
		Paths:          []string{root},
		Profile:        model.ProfileRepo,
		MaxBytes:       DefaultMaxBytes,
		Workers:        2,
		MaxFindings:    50,
		Incremental:    true,
		StateCachePath: cachePath,
		ScanStyle:      model.ScanStylePattern,
		PolicyChecks:   false,
		Logger:         logging.NewLogger(logging.LogError, io.Discard),
	})
	if err != nil {
		t.Fatalf("scan with corrupt cache: %v", err)
	}
	if rep.ScannedFiles < 1 {
		t.Fatalf("expected at least one scanned file, got %d", rep.ScannedFiles)
	}
}

func TestThresholdExceeded_SkipsSuppressed(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{
		{RuleID: "R-1", Severity: model.SeverityCritical, Suppressed: true},
		{RuleID: "R-2", Severity: model.SeverityLow},
	}
	if ThresholdExceeded(findings, model.SeverityHigh, "") {
		t.Fatal("suppressed critical finding should not trigger threshold")
	}
	findings[0].Suppressed = false
	if !ThresholdExceeded(findings, model.SeverityHigh, "") {
		t.Fatal("unsuppressed critical finding should trigger threshold")
	}
}

func TestSummarizeFindings_SkipsSuppressed(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{
		{RuleID: "R-1", Severity: model.SeverityCritical, Suppressed: true},
		{RuleID: "R-2", Severity: model.SeverityHigh},
		{RuleID: "R-3", Severity: model.SeverityHigh, Suppressed: true},
	}
	summary := SummarizeFindings(findings)
	if summary[string(model.SeverityCritical)] != 0 {
		t.Fatalf("suppressed critical should be 0, got %d", summary[string(model.SeverityCritical)])
	}
	if summary[string(model.SeverityHigh)] != 1 {
		t.Fatalf("expected 1 high (2 minus 1 suppressed), got %d", summary[string(model.SeverityHigh)])
	}
}

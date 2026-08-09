package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
)

func TestParseProfileAndOutputFormat(t *testing.T) {
	if _, err := model.ParseProfile("repo"); err != nil {
		t.Fatalf("ParseProfile(repo) failed: %v", err)
	}
	if _, err := model.ParseProfile("nope"); err == nil {
		t.Fatalf("expected ParseProfile invalid input to fail")
	}

	if _, err := parseOutputFormat("sarif"); err != nil {
		t.Fatalf("parseOutputFormat(sarif) failed: %v", err)
	}
	if _, err := parseOutputFormat("bogus"); err == nil {
		t.Fatalf("expected parseOutputFormat invalid input to fail")
	}
}

func TestCanonicalizePathsAndExpandHome(t *testing.T) {
	paths, err := canonicalizePaths([]string{" . ", ".", ""})
	if err != nil {
		t.Fatalf("canonicalizePaths failed: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected deduped single path, got %v", paths)
	}
	if _, err := canonicalizePaths([]string{" ", ""}); err == nil {
		t.Fatalf("expected empty canonicalizePaths call to fail")
	}

	got := model.ExpandHomePath("~/folder")
	if strings.HasPrefix(got, "~") {
		t.Fatalf("expected home-expanded path, got %q", got)
	}
}

func TestResolveScanRootsProfiles(t *testing.T) {
	roots, err := resolveScanRoots(".", "", model.ProfileContainer)
	if err != nil {
		t.Fatalf("resolve roots failed: %v", err)
	}
	if len(roots) != 1 || roots[0] != "/" {
		t.Fatalf("expected container profile to default to '/', got %v", roots)
	}

	devRoots, err := resolveScanRoots(".", "", model.ProfileDeveloper)
	if err != nil {
		t.Fatalf("resolve developer roots failed: %v", err)
	}
	if len(devRoots) == 0 {
		t.Fatalf("expected developer profile to produce at least one root")
	}
}

func TestExtractGlobalFlags(t *testing.T) {
	assertArgs := func(t *testing.T, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("args len = %d, want %d: got %v", len(got), len(want), got)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("args[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	}

	t.Run("no flags", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"corpus", "scan"})
		if gf.Verbosity != 0 {
			t.Errorf("verbosity = %d, want 0", gf.Verbosity)
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("-v 2 before subcommand", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"-v", "2", "corpus", "scan"})
		if gf.Verbosity != 2 {
			t.Errorf("verbosity = %d, want 2", gf.Verbosity)
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("--verbose 1", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"--verbose", "1", "corpus", "scan"})
		if gf.Verbosity != 1 {
			t.Errorf("verbosity = %d, want 1", gf.Verbosity)
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("--verbose=3", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"--verbose=3", "corpus", "scan"})
		if gf.Verbosity != 3 {
			t.Errorf("verbosity = %d, want 3", gf.Verbosity)
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("-v after subcommand", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"corpus", "-v", "2", "scan"})
		if gf.Verbosity != 2 {
			t.Errorf("verbosity = %d, want 2", gf.Verbosity)
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("stops at --", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"--", "-v", "2"})
		if gf.Verbosity != 0 {
			t.Errorf("verbosity = %d, want 0", gf.Verbosity)
		}
		assertArgs(t, rest, []string{"--", "-v", "2"})
	})

	t.Run("--quiet", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"-q", "corpus", "scan"})
		if !gf.Quiet {
			t.Error("expected Quiet=true")
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("--cpu-profile", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"--cpu-profile", "cpu.prof", "corpus", "scan"})
		if gf.CPUProfile != "cpu.prof" {
			t.Errorf("CPUProfile = %q, want cpu.prof", gf.CPUProfile)
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("--perf-debug", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"--perf-debug", "corpus", "scan"})
		if !gf.PerfDebug {
			t.Error("expected PerfDebug=true")
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("--config with =", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"--config=/etc/skeptic.json", "corpus", "scan"})
		if gf.Config != "/etc/skeptic.json" {
			t.Errorf("Config = %q, want /etc/skeptic.json", gf.Config)
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("-c shorthand for --config", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"-c", "/tmp/my.json", "corpus", "scan"})
		if gf.Config != "/tmp/my.json" {
			t.Errorf("Config = %q, want /tmp/my.json", gf.Config)
		}
		assertArgs(t, rest, []string{"corpus", "scan"})
	})

	t.Run("multiple global flags", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"-v", "2", "--cpu-profile", "cpu.prof", "--trace", "trace.out", "-q", "corpus", "scan", "-f", "json"})
		if gf.Verbosity != 2 {
			t.Errorf("verbosity = %d, want 2", gf.Verbosity)
		}
		if gf.CPUProfile != "cpu.prof" {
			t.Errorf("CPUProfile = %q", gf.CPUProfile)
		}
		if gf.Trace != "trace.out" {
			t.Errorf("Trace = %q", gf.Trace)
		}
		if !gf.Quiet {
			t.Error("expected Quiet=true")
		}
		assertArgs(t, rest, []string{"corpus", "scan", "-f", "json"})
	})

	t.Run("--log-file and --mem-profile", func(t *testing.T) {
		gf, rest := extractGlobalFlags([]string{"--log-file", "/tmp/skeptic.log", "--mem-profile", "mem.prof", "corpus", "info"})
		if gf.LogFile != "/tmp/skeptic.log" {
			t.Errorf("LogFile = %q", gf.LogFile)
		}
		if gf.MemProfile != "mem.prof" {
			t.Errorf("MemProfile = %q", gf.MemProfile)
		}
		assertArgs(t, rest, []string{"corpus", "info"})
	})
}

func TestMergeGlobalFlagsIntoArgs(t *testing.T) {
	gf := globalFlags{Verbosity: 2, CPUProfile: "cpu.prof", Quiet: true}
	merged := mergeGlobalFlagsIntoArgs(gf, []string{"--path", "."}, true)
	found := map[string]bool{}
	for _, a := range merged {
		found[a] = true
	}
	if !found["--verbose"] || !found["--quiet"] || !found["--cpu-profile"] {
		t.Fatalf("missing expected flags in merged args: %v", merged)
	}

	empty := mergeGlobalFlagsIntoArgs(globalFlags{}, []string{"scan"}, true)
	if len(empty) != 1 || empty[0] != "scan" {
		t.Fatalf("expected passthrough for empty gf, got %v", empty)
	}
}

func TestLooksLikeHexPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"deadbeef", true},
		{"abcd1234", true},
		{"ABCD1234", true},
		{"abc", false},
		{"abcg", false},
		{"init", false},
		{"scan", false},
		{"abcdef12", true},
		{"ab", false},
	}
	for _, tc := range cases {
		got := looksLikeHexPrefix(tc.in)
		if got != tc.want {
			t.Errorf("looksLikeHexPrefix(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestLooksLikePath(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"./my-repo", true},
		{"../parent", true},
		{"/absolute/path", true},
		{".", true},
		{"..", true},
		{"~/projects", true},
		{"relative/dir", true},
		{"scan", false},
		{"ingest", false},
	}
	for _, tc := range cases {
		got := looksLikePath(tc.in)
		if got != tc.want {
			t.Errorf("looksLikePath(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestPositionalArgAsScanPath(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "hello.txt", "hello world")

	t.Setenv("HOME", dir)
	var stdout, stderr strings.Builder
	_, code := performSkepticRun(
		[]string{dir, "--quiet", "--max-files", "10", "--config", "", "--waivers", ""},
		&stdout, &stderr, scanpkg.ScanWithOptions, skepticRunMode{},
	)
	if code != 0 {
		t.Fatalf("expected exit 0 scanning %s, got %d: %s", dir, code, stderr.String())
	}
}

func TestPositionalArgConflictsWithPathFlag(t *testing.T) {
	var stdout, stderr strings.Builder
	_, code := performSkepticRun(
		[]string{"--path", "/tmp", "/other"},
		&stdout, &stderr, scanpkg.ScanWithOptions, skepticRunMode{},
	)
	if code != 2 {
		t.Fatalf("expected exit 2 for conflicting --path and positional, got %d", code)
	}
	if !strings.Contains(stderr.String(), "unexpected positional") {
		t.Errorf("expected conflict error, got: %s", stderr.String())
	}
}

func writeFixture(t *testing.T, root string, relPath string, content string) {
	t.Helper()
	path := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed for %s: %v", relPath, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write failed for %s: %v", relPath, err)
	}
}

func TestEmitReportToFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "report.json")
	report := model.Report{
		TargetPath: "/tmp/example",
		Findings:   []model.Finding{{RuleID: "SCM-TRUST-001", Severity: model.SeverityHigh}},
	}

	var stdout, stderr bytes.Buffer
	if _, code := emitReport(&stdout, &stderr, report, model.FormatJSON, out); code != 0 {
		t.Fatalf("emitReport code = %d, stderr = %s", code, stderr.String())
	}

	if stdout.Len() != 0 {
		t.Errorf("stdout should stay empty when --out is set, got %q", stdout.String())
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var decoded model.Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	if len(decoded.Findings) != 1 || decoded.Findings[0].RuleID != "SCM-TRUST-001" {
		t.Errorf("findings did not round-trip: %+v", decoded.Findings)
	}
}

func TestEmitReportEmptyOutPathGoesToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	report := model.Report{TargetPath: "/tmp/example"}

	if _, code := emitReport(&stdout, &stderr, report, model.FormatJSON, ""); code != 0 {
		t.Fatalf("emitReport code = %d, stderr = %s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Error("expected the report on stdout when --out is empty")
	}
}

func TestEmitReportUnwritableOutPathFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions do not deny writes")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

	var stdout, stderr bytes.Buffer
	_, code := emitReport(&stdout, &stderr, model.Report{}, model.FormatJSON, filepath.Join(locked, "r.json"))
	if code == 0 {
		t.Error("expected a non-zero code when the report cannot be written")
	}
	if !strings.Contains(stderr.String(), "failed to write report") {
		t.Errorf("stderr should name the failure, got %q", stderr.String())
	}
}

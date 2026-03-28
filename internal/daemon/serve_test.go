package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestResolveServeInterval(t *testing.T) {
	d, err := ResolveServeInterval("5m", "")
	if err != nil {
		t.Fatalf("ResolveServeInterval failed: %v", err)
	}
	if d.String() != "5m0s" {
		t.Fatalf("unexpected interval: %s", d)
	}

	cronDur, err := ResolveServeInterval("", "@every 30s")
	if err != nil {
		t.Fatalf("ResolveServeInterval cron failed: %v", err)
	}
	if cronDur.String() != "30s" {
		t.Fatalf("unexpected cron duration: %s", cronDur)
	}

	if _, err := ResolveServeInterval("5m", "* * * * *"); err == nil {
		t.Fatalf("expected unsupported cron syntax to fail")
	}
}

func TestSanitizeServeScanArgs(t *testing.T) {
	args, err := SanitizeServeScanArgs([]string{"--path", "."})
	if err != nil {
		t.Fatalf("SanitizeServeScanArgs failed: %v", err)
	}
	if len(args) != 2 {
		t.Fatalf("unexpected arg count: %d", len(args))
	}
	blocked := []string{"serve", "daemon", "ingest", "sign-rulepack", "gen-rule-keypair", "init-config", "init", "config"}
	for _, sub := range blocked {
		if _, err := SanitizeServeScanArgs([]string{sub}); err == nil {
			t.Fatalf("expected %q to be blocked", sub)
		}
	}
	empty, err := SanitizeServeScanArgs(nil)
	if err != nil {
		t.Fatalf("empty args should not fail: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected empty result, got %d", len(empty))
	}
}

func TestServeAuthOK(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://localhost/status", nil)
	req.Header.Set("Authorization", "Bearer abc123")
	if !ServeAuthOK(req, "abc123", false) {
		t.Fatalf("expected auth header to pass")
	}
	req.Header.Set("Authorization", "Bearer wrong")
	if ServeAuthOK(req, "abc123", false) {
		t.Fatalf("expected invalid token to fail")
	}
	if !ServeAuthOK(req, "", true) {
		t.Fatalf("expected allow-unauthenticated mode to pass")
	}
}

func TestFormatTimestamp(t *testing.T) {
	if got := FormatTimestamp(time.Time{}); got != "" {
		t.Fatalf("zero time: want empty string, got %q", got)
	}
	ts := time.Date(2024, 3, 15, 14, 30, 45, 0, time.FixedZone("CET", 3600))
	if got := FormatTimestamp(ts); got != "2024-03-15T13:30:45Z" {
		t.Fatalf("RFC3339 UTC: got %q want %q", got, "2024-03-15T13:30:45Z")
	}
}

func TestParseServeFlagsDefaults(t *testing.T) {
	var stderr strings.Builder
	cfg, err := ParseServeFlags([]string{}, &stderr)
	if err != nil {
		t.Fatalf("ParseServeFlags: %v", err)
	}
	if cfg.BindAddr != "127.0.0.1:7788" {
		t.Errorf("bind = %q, want 127.0.0.1:7788", cfg.BindAddr)
	}
	if cfg.Interval != 5*time.Minute {
		t.Errorf("interval = %v, want 5m", cfg.Interval)
	}
	if !cfg.RunOnStart {
		t.Error("run-on-start should default true")
	}
}

func TestParseServeFlagsDryRun(t *testing.T) {
	var stderr strings.Builder
	cfg, err := ParseServeFlags([]string{"--dry-run", "--bind", "127.0.0.1:9999"}, &stderr)
	if err != nil {
		t.Fatalf("ParseServeFlags: %v", err)
	}
	if !cfg.DryRun {
		t.Error("expected dry-run=true")
	}
	if cfg.BindAddr != "127.0.0.1:9999" {
		t.Errorf("bind = %q", cfg.BindAddr)
	}
}

func TestParseServeFlagsHelp(t *testing.T) {
	var stderr strings.Builder
	_, err := ParseServeFlags([]string{"-h"}, &stderr)
	if err != ErrServeHelpRequested {
		t.Fatalf("expected ErrServeHelpRequested, got %v", err)
	}
}

func TestParseServeFlagsBadInterval(t *testing.T) {
	var stderr strings.Builder
	_, err := ParseServeFlags([]string{"--scan-interval", "nope"}, &stderr)
	if err == nil {
		t.Fatal("expected error for bad interval")
	}
}

func TestGenerateServeToken(t *testing.T) {
	tok, err := GenerateServeToken()
	if err != nil {
		t.Fatalf("GenerateServeToken: %v", err)
	}
	if len(tok) != 48 {
		t.Errorf("token len = %d, want 48 hex chars", len(tok))
	}
	tok2, _ := GenerateServeToken()
	if tok == tok2 {
		t.Error("two generated tokens should differ")
	}
}

func TestBeginRunEndRun(t *testing.T) {
	state := &DaemonRuntimeState{}
	if !state.BeginRun("test") {
		t.Fatal("first BeginRun should succeed")
	}
	if state.BeginRun("test2") {
		t.Fatal("second BeginRun while running should fail")
	}
	state.EndRun(model.Report{ScannedFiles: 5, Findings: []model.Finding{{RuleID: "R1"}}}, 0, nil)
	if state.scanCount != 1 {
		t.Errorf("scanCount = %d", state.scanCount)
	}
	if state.totalFindings != 1 {
		t.Errorf("totalFindings = %d", state.totalFindings)
	}
	if !state.hasReport {
		t.Error("expected hasReport=true after successful EndRun")
	}
}

func TestEndRunWithError(t *testing.T) {
	state := &DaemonRuntimeState{}
	state.BeginRun("errtest")
	state.EndRun(model.Report{}, 1, fmt.Errorf("scan failed"))
	if state.lastError != "scan failed" {
		t.Errorf("lastError = %q", state.lastError)
	}
	if state.hasReport {
		t.Error("hasReport should be false after error")
	}
}

func TestStatusAndReport(t *testing.T) {
	state := &DaemonRuntimeState{}
	_, ok := state.Report()
	if ok {
		t.Fatal("Report should return false when no report exists")
	}

	state.BeginRun("test")
	state.EndRun(model.Report{ScannedFiles: 3}, 0, nil)

	report, ok := state.Report()
	if !ok {
		t.Fatal("Report should return true after EndRun")
	}
	if report.ScannedFiles != 3 {
		t.Errorf("scanned files = %d", report.ScannedFiles)
	}

	status := state.Status("127.0.0.1:7788", 5*time.Minute)
	if status.ScanCount != 1 {
		t.Errorf("status scan count = %d", status.ScanCount)
	}
	if status.LastReason != "test" {
		t.Errorf("status last reason = %q", status.LastReason)
	}
}

func TestSetNextRun(t *testing.T) {
	state := &DaemonRuntimeState{}
	next := time.Now().Add(10 * time.Minute)
	state.SetNextRun(next)
	status := state.Status("127.0.0.1:7788", 5*time.Minute)
	if status.NextRunAt == "" {
		t.Error("expected non-empty NextRunAt")
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, http.StatusOK, map[string]string{"key": "val"})
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if body["key"] != "val" {
		t.Errorf("body = %v", body)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), "skeptic_scans_total") {
		t.Error("expected prometheus metrics in body")
	}
}

func TestReportEndpointWithData(t *testing.T) {
	state := &DaemonRuntimeState{}
	state.BeginRun("test")
	state.EndRun(model.Report{ScannedFiles: 7, FindingsBySeverity: map[string]int{"high": 1}}, 0, nil)
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/report", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/report status = %d, want 200", w.Code)
	}
	var report model.Report
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if report.ScannedFiles != 7 {
		t.Errorf("scanned files = %d", report.ScannedFiles)
	}
}

func TestServeDryRunAuthModeValues(t *testing.T) {
	cases := []struct {
		token, file string
		unauth      bool
		want        string
	}{
		{"", "", true, "unauthenticated (open)"},
		{"tok", "", false, "bearer token (inline)"},
		{"", "file.txt", false, "bearer token (file)"},
		{"", "", false, "ephemeral (auto-generated)"},
	}
	for _, tc := range cases {
		got := ServeDryRunAuthMode(tc.token, tc.file, tc.unauth)
		if got != tc.want {
			t.Errorf("ServeDryRunAuthMode(%q,%q,%v) = %q, want %q", tc.token, tc.file, tc.unauth, got, tc.want)
		}
	}
}

func TestApplyGlobalFlagsToDaemonConfig(t *testing.T) {
	t.Run("global verbosity applied when serve flag not set", func(t *testing.T) {
		cfg := DaemonConfig{Verbosity: 0, visitedFlags: map[string]struct{}{}}
		applyGlobalFlagsToDaemonConfig(&cfg, GlobalFlagOverrides{Verbosity: 2})
		if cfg.Verbosity != 2 {
			t.Errorf("verbosity = %d, want 2", cfg.Verbosity)
		}
	})
	t.Run("serve flag takes precedence over global", func(t *testing.T) {
		cfg := DaemonConfig{Verbosity: 1, visitedFlags: map[string]struct{}{"verbose": {}}}
		applyGlobalFlagsToDaemonConfig(&cfg, GlobalFlagOverrides{Verbosity: 3})
		if cfg.Verbosity != 1 {
			t.Errorf("verbosity = %d, want 1 (serve flag should win)", cfg.Verbosity)
		}
	})
	t.Run("global quiet applied", func(t *testing.T) {
		cfg := DaemonConfig{visitedFlags: map[string]struct{}{}}
		applyGlobalFlagsToDaemonConfig(&cfg, GlobalFlagOverrides{Quiet: true})
		if !cfg.Quiet {
			t.Error("expected quiet=true")
		}
	})
	t.Run("global config applied", func(t *testing.T) {
		cfg := DaemonConfig{visitedFlags: map[string]struct{}{}}
		applyGlobalFlagsToDaemonConfig(&cfg, GlobalFlagOverrides{Config: "/etc/skeptic.json"})
		if cfg.ConfigPath != "/etc/skeptic.json" {
			t.Errorf("config = %q, want /etc/skeptic.json", cfg.ConfigPath)
		}
	})
	t.Run("global log-file applied when serve flag not set", func(t *testing.T) {
		cfg := DaemonConfig{visitedFlags: map[string]struct{}{}}
		applyGlobalFlagsToDaemonConfig(&cfg, GlobalFlagOverrides{LogFile: "/tmp/skeptic.log"})
		if cfg.LogFilePath != "/tmp/skeptic.log" {
			t.Errorf("log-file = %q, want /tmp/skeptic.log", cfg.LogFilePath)
		}
	})
}

func TestApplySystemConfigToDaemon(t *testing.T) {
	t.Run("system bind applied when flag not set", func(t *testing.T) {
		cfg := DaemonConfig{BindAddr: "127.0.0.1:7788", visitedFlags: map[string]struct{}{}}
		applySystemConfigToDaemon(&cfg, SystemDaemonConfig{DaemonBind: "0.0.0.0:9900"})
		if cfg.BindAddr != "0.0.0.0:9900" {
			t.Errorf("bind = %q, want 0.0.0.0:9900", cfg.BindAddr)
		}
	})
	t.Run("explicit bind flag wins over system config", func(t *testing.T) {
		cfg := DaemonConfig{BindAddr: "127.0.0.1:1234", visitedFlags: map[string]struct{}{"bind": {}}}
		applySystemConfigToDaemon(&cfg, SystemDaemonConfig{DaemonBind: "0.0.0.0:9900"})
		if cfg.BindAddr != "127.0.0.1:1234" {
			t.Errorf("bind = %q, want 127.0.0.1:1234 (flag should win)", cfg.BindAddr)
		}
	})
	t.Run("empty system bind does not override default", func(t *testing.T) {
		cfg := DaemonConfig{BindAddr: "127.0.0.1:7788", visitedFlags: map[string]struct{}{}}
		applySystemConfigToDaemon(&cfg, SystemDaemonConfig{})
		if cfg.BindAddr != "127.0.0.1:7788" {
			t.Errorf("bind = %q, want 127.0.0.1:7788", cfg.BindAddr)
		}
	})
}

func TestBuildDaemonScanArgs(t *testing.T) {
	t.Run("config and verbosity prepended", func(t *testing.T) {
		cfg := DaemonConfig{
			ConfigPath: "/etc/skeptic.json",
			Verbosity:  2,
			ScanArgs:   []string{"--path", "."},
		}
		got := buildDaemonScanArgs(cfg)
		want := []string{"--config", "/etc/skeptic.json", "--verbose", "2", "--path", "."}
		if len(got) != len(want) {
			t.Fatalf("len = %d, want %d: %v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("arg[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})
	t.Run("no extras returns original scan args", func(t *testing.T) {
		cfg := DaemonConfig{ScanArgs: []string{"--path", "."}}
		got := buildDaemonScanArgs(cfg)
		if len(got) != 2 || got[0] != "--path" {
			t.Errorf("expected original scan args, got %v", got)
		}
	})
	t.Run("quiet flag prepended", func(t *testing.T) {
		cfg := DaemonConfig{Quiet: true, ScanArgs: []string{}}
		got := buildDaemonScanArgs(cfg)
		if len(got) != 1 || got[0] != "--quiet" {
			t.Errorf("expected [--quiet], got %v", got)
		}
	})
}

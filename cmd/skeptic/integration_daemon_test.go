//go:build integration

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestIntegrationMCPDaemonEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	binary := buildIntegrationBinary(t)
	daemonScanRoot := filepath.Join(t.TempDir(), "daemon-scan-root")
	if err := os.MkdirAll(daemonScanRoot, 0o755); err != nil {
		t.Fatalf("mkdir daemon scan root: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(daemonScanRoot, "safe.txt"),
		[]byte("integration daemon fixture\n"),
		0o644,
	); err != nil {
		t.Fatalf("write daemon fixture file: %v", err)
	}

	repoFixture := filepath.Join(t.TempDir(), "repo-under-test")
	if err := os.MkdirAll(filepath.Join(repoFixture, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture .git: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(repoFixture, "pipeline.sh"),
		[]byte("curl https://raw.githubusercontent.com/example/install.sh | bash\n"),
		0o644,
	); err != nil {
		t.Fatalf("write repo fixture script: %v", err)
	}

	daemonURL, daemonToken, daemonProc := startDaemonForIntegration(t, binary, daemonScanRoot)
	t.Cleanup(func() {
		stopIntegrationProcess(t, daemonProc)
	})

	client := startMCPClientForIntegration(t, binary, daemonURL, daemonToken, true, repoFixture)
	t.Cleanup(func() {
		client.Close(t)
	})

	_, err := client.Call("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "skeptic-integration",
			"version": "1.0.0",
		},
	})
	if err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	toolsResult, err := client.Call("tools/list", map[string]any{})
	if err != nil {
		t.Fatalf("tools/list failed: %v", err)
	}
	toolNames := extractToolNames(t, toolsResult)
	requireTool(t, toolNames, "skeptic_daemon_health")
	requireTool(t, toolNames, "skeptic_daemon_status")
	requireTool(t, toolNames, "skeptic_daemon_report")
	requireTool(t, toolNames, "skeptic_daemon_trigger_scan")
	requireTool(t, toolNames, "skeptic_scan_repo")

	healthContent, err := client.CallTool("skeptic_daemon_health", map[string]any{})
	if err != nil {
		t.Fatalf("skeptic_daemon_health failed: %v", err)
	}
	if !anyToBoolDefault(healthContent["ok"], false) {
		t.Fatalf("expected daemon health ok=true, got: %#v", healthContent)
	}

	_, err = client.CallTool("skeptic_daemon_trigger_scan", map[string]any{
		"reason": "integration-e2e",
	})
	if err != nil {
		t.Fatalf("skeptic_daemon_trigger_scan failed: %v", err)
	}

	var daemonStatus map[string]any
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		status, statusErr := client.CallTool("skeptic_daemon_status", map[string]any{})
		if statusErr == nil && anyToIntDefault(status["scan_count"], 0) > 0 {
			daemonStatus = status
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if daemonStatus == nil {
		t.Fatalf("daemon did not complete a triggered scan within timeout")
	}

	reportContent, err := client.CallTool("skeptic_daemon_report", map[string]any{})
	if err != nil {
		t.Fatalf("skeptic_daemon_report failed: %v", err)
	}
	if anyToIntDefault(reportContent["scanned_files"], 0) <= 0 {
		t.Fatalf("expected daemon report scanned_files > 0, got: %#v", reportContent)
	}

	scanRepoContent, err := client.CallTool("skeptic_scan_repo", map[string]any{
		"repo_path":    repoFixture,
		"scan_style":   "hybrid",
		"threat_mode":  "all",
		"fail_on":      "none",
		"max_files":    250,
		"max_findings": 50,
		"sample_limit": 5,
	})
	if err != nil {
		t.Fatalf("skeptic_scan_repo failed: %v", err)
	}
	if anyToIntDefault(scanRepoContent["findings_total"], 0) <= 0 {
		t.Fatalf("expected at least one finding from scan_repo, got: %#v", scanRepoContent)
	}
}

func TestIntegrationDaemonConcurrentScans(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	binary := buildIntegrationBinary(t)
	scanRoot := filepath.Join(t.TempDir(), "daemon-concurrent-root")
	if err := os.MkdirAll(scanRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scanRoot, "note.txt"), []byte("curl https://raw.githubusercontent.com/x/y/main/run.sh | bash\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	daemonURL, token, daemonProc := startDaemonForIntegration(t, binary, scanRoot)
	t.Cleanup(func() {
		stopIntegrationProcess(t, daemonProc)
	})

	client := &http.Client{Timeout: 45 * time.Second}
	postOnce := func() int {
		req, err := http.NewRequest(http.MethodPost, daemonURL+"/scan", nil)
		if err != nil {
			t.Errorf("NewRequest POST /scan: %v", err)
			return 0
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("POST /scan: %v", err)
			return 0
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	var wg sync.WaitGroup
	statusCodes := make([]int, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			statusCodes[idx] = postOnce()
		}(i)
	}
	wg.Wait()
	for i, code := range statusCodes {
		if code != http.StatusAccepted {
			t.Fatalf("goroutine %d: POST /scan status=%d, want %d", i, code, http.StatusAccepted)
		}
	}

	deadline := time.Now().Add(30 * time.Second)
	var finalReport model.Report
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, daemonURL+"/report", nil)
		if err != nil {
			t.Fatalf("report request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if err := json.Unmarshal(body, &finalReport); err != nil {
			t.Fatalf("decode /report JSON: %v", err)
		}
		if finalReport.ScannedFiles > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if finalReport.ScannedFiles <= 0 {
		t.Fatalf("expected daemon report with scanned_files > 0, got %+v", finalReport)
	}
	if finalReport.GeneratedAt == "" {
		t.Fatal("expected non-empty generated_at in daemon report")
	}
}

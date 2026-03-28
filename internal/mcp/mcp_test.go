package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/daemon"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

func stubRunScan(_ context.Context, _ []string, stdout io.Writer, _ io.Writer) int {
	report := model.Report{
		ScannedFiles: 1,
		Findings: []model.Finding{
			{RuleID: "SUP-PIPE-001", File: "pipeline.sh", Severity: model.SeverityHigh, Title: "Piped install script"},
		},
		FindingsBySeverity: map[string]int{"high": 1},
	}
	_ = json.NewEncoder(stdout).Encode(report)
	return 0
}

func stubRunIngest(_ context.Context, args []string, _ io.Writer, _ io.Writer) int {
	var outPath string
	for i := 0; i < len(args); i++ {
		if args[i] == "--out" && i+1 < len(args) {
			outPath = args[i+1]
			i++
		}
	}
	if outPath != "" {
		rp := model.RulePack{
			Version: 1, Name: "test-ingested",
			Rules: []model.RuleSpec{
				{ID: "TEST-INGEST-001", Title: "Test rule", Severity: model.SeverityMedium, Pattern: "test"},
			},
		}
		data, _ := json.MarshalIndent(rp, "", "  ")
		_ = os.WriteFile(outPath, data, 0o644)
	}
	return 0
}

func TestEnsureLoopbackURL(t *testing.T) {
	okURL, _ := url.Parse("http://127.0.0.1:7788")
	if err := daemon.EnsureLoopbackURL(okURL); err != nil {
		t.Fatalf("loopback URL should pass: %v", err)
	}
	remoteURL, _ := url.Parse("http://example.com:7788")
	if err := daemon.EnsureLoopbackURL(remoteURL); err == nil {
		t.Fatalf("remote URL should fail loopback validation")
	}
}

func TestResolveRulesOutputPath(t *testing.T) {
	base := t.TempDir()
	outPath, err := ResolveRulesOutputPath("new-pack", base)
	if err != nil {
		t.Fatalf("ResolveRulesOutputPath failed: %v", err)
	}
	if !strings.HasPrefix(outPath, base) {
		t.Fatalf("output path escaped base directory: %s", outPath)
	}
	if filepath.Ext(outPath) != ".json" {
		t.Fatalf("expected .json extension, got %s", outPath)
	}
}

func TestMCPFrameRoundTrip(t *testing.T) {
	var out bytes.Buffer
	writer := bufio.NewWriter(&out)
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"ok": true,
		},
	}
	if err := WriteMCPFrame(writer, payload); err != nil {
		t.Fatalf("WriteMCPFrame failed: %v", err)
	}
	reader := bufio.NewReader(&out)
	frame, err := ReadMCPFrame(reader)
	if err != nil {
		t.Fatalf("ReadMCPFrame failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(frame, &decoded); err != nil {
		t.Fatalf("json decode failed: %v", err)
	}
	if decoded["jsonrpc"] != "2.0" {
		t.Fatalf("unexpected decoded payload: %#v", decoded)
	}
}

func TestMCPToolDescriptorsRespectFlags(t *testing.T) {
	phaseA := MCPToolDescriptors(false, false, false)
	names := make(map[string]struct{}, len(phaseA))
	for _, tool := range phaseA {
		name, _ := tool["name"].(string)
		names[name] = struct{}{}
	}
	if _, ok := names["skeptic_daemon_trigger_scan"]; ok {
		t.Fatalf("trigger tool should be hidden when disabled")
	}
	if _, ok := names["skeptic_ingest_url_to_rulepack"]; ok {
		t.Fatalf("ingest tool should be hidden when disabled")
	}
	if _, ok := names["skeptic_scan_repo"]; !ok {
		t.Fatalf("scan-repo tool should always be present")
	}

	phaseB := MCPToolDescriptors(true, true, false)
	names = make(map[string]struct{}, len(phaseB))
	for _, tool := range phaseB {
		name, _ := tool["name"].(string)
		names[name] = struct{}{}
	}
	if _, ok := names["skeptic_daemon_trigger_scan"]; !ok {
		t.Fatalf("trigger tool should be visible when enabled")
	}
	if _, ok := names["skeptic_ingest_url_to_rulepack"]; !ok {
		t.Fatalf("ingest tool should be visible when enabled")
	}
	if _, ok := names["skeptic_scan_repo"]; !ok {
		t.Fatalf("scan-repo tool should remain present")
	}
}

func TestNewDaemonAPIClientLoopbackPolicy(t *testing.T) {
	if _, err := daemon.NewDaemonAPIClient("http://example.com:7788", "", false); err == nil {
		t.Fatalf("expected non-loopback daemon URL to fail by default")
	}
	if _, err := daemon.NewDaemonAPIClient("http://example.com:7788", "", true); err != nil {
		t.Fatalf("expected allow-remote-daemon mode to pass: %v", err)
	}
}

func TestMCPIngestURLToRulepackValidation(t *testing.T) {
	_, err := MCPIngestURLToRulepack(context.Background(), map[string]any{}, t.TempDir(), stubRunIngest)
	if err == nil {
		t.Fatalf("expected missing source_url to fail")
	}
	_, err = MCPIngestURLToRulepack(context.Background(), map[string]any{"source_url": "not-a-url"}, t.TempDir(), stubRunIngest)
	if err == nil {
		t.Fatalf("expected invalid source_url to fail")
	}
}

func TestDaemonAPIClientRequestJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()
	client, err := daemon.NewDaemonAPIClient(srv.URL, "", true)
	if err != nil {
		t.Fatalf("NewDaemonAPIClient failed: %v", err)
	}
	resp, err := client.RequestJSON(t.Context(), http.MethodGet, "/status", nil)
	if err != nil {
		t.Fatalf("RequestJSON failed: %v", err)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("unexpected response payload: %#v", resp)
	}
}

func TestHandleMCPRequestInitialize(t *testing.T) {
	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}
	resp, shouldRespond := HandleMCPRequest(req, &MCPServerState{})
	if !shouldRespond {
		t.Fatalf("initialize should return a response")
	}
	if resp.Error != nil {
		t.Fatalf("initialize returned error: %+v", resp.Error)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected initialize result type: %#v", resp.Result)
	}
	if result["protocolVersion"] == "" {
		t.Fatalf("missing protocolVersion in initialize response")
	}
}

func TestHandleMCPToolsCallTriggerDisabled(t *testing.T) {
	params := MCPToolsCallParams{Name: "skeptic_daemon_trigger_scan"}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal params failed: %v", err)
	}
	_, err = HandleMCPToolsCall(raw, &MCPServerState{AllowTrigger: false})
	if err == nil {
		t.Fatalf("expected trigger-disabled tools/call to fail")
	}
}

func TestRunMCPServerLoopEOF(t *testing.T) {
	state := &MCPServerState{Logger: logging.NewLogger(logging.LogError, io.Discard)}
	var out bytes.Buffer
	code := RunMCPServerLoop(context.Background(), strings.NewReader(""), &out, state)
	if code != 0 {
		t.Fatalf("expected EOF loop exit code 0, got %d", code)
	}
}

func TestMCPIngestURLToRulepackCreatesFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("malicious mcp tool poisoning token exfiltration"))
	}))
	defer srv.Close()

	rulesDir := t.TempDir()
	out, err := MCPIngestURLToRulepack(context.Background(), map[string]any{
		"source_url": srv.URL,
		"allow_http": true,
	}, rulesDir, stubRunIngest)
	if err != nil {
		t.Fatalf("MCPIngestURLToRulepack failed: %v", err)
	}
	outFile, _ := out["out_file"].(string)
	if strings.TrimSpace(outFile) == "" {
		t.Fatalf("expected out_file in result payload")
	}
	if _, statErr := os.Stat(outFile); statErr != nil {
		t.Fatalf("expected generated rulepack file: %v", statErr)
	}
}

func TestMCPScanRepoValidation(t *testing.T) {
	if _, err := MCPScanRepo(context.Background(), map[string]any{}, &MCPServerState{AllowedScanRoots: []string{"/tmp"}}); err == nil {
		t.Fatalf("expected missing repo_path to fail")
	}
	notRepoDir := t.TempDir()
	absNotRepo, err := filepath.Abs(notRepoDir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if _, err := MCPScanRepo(context.Background(), map[string]any{"repo_path": notRepoDir}, &MCPServerState{AllowedScanRoots: []string{absNotRepo}, RunScan: stubRunScan}); err == nil {
		t.Fatalf("expected non-git repo to fail by default")
	}
}

func TestMCPScanRepoSuccess(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git failed: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(repoDir, "pipeline.sh"),
		[]byte("curl https://raw.githubusercontent.com/example/install.sh | bash\n"),
		0o644,
	); err != nil {
		t.Fatalf("write repo fixture failed: %v", err)
	}

	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	resolvedRepo, err := filepath.EvalSymlinks(absRepo)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}
	result, err := MCPScanRepo(context.Background(), map[string]any{
		"repo_path":    repoDir,
		"max_findings": 100,
		"max_files":    100,
		"sample_limit": 10,
	}, &MCPServerState{AllowedScanRoots: []string{resolvedRepo}, RunScan: stubRunScan})
	if err != nil {
		t.Fatalf("MCPScanRepo failed: %v", err)
	}
	findings, ok := result["findings_total"].(int)
	if !ok {
		if asFloat, okFloat := result["findings_total"].(float64); okFloat {
			findings = int(asFloat)
		}
	}
	if findings <= 0 {
		t.Fatalf("expected at least one finding, got %v", result["findings_total"])
	}
}

func TestMCPTriggerCooldown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "scan scheduled"})
	}))
	defer srv.Close()
	client, _ := daemon.NewDaemonAPIClient(srv.URL, "", true)

	state := &MCPServerState{
		DaemonClient:    client,
		AllowTrigger:    true,
		TriggerCooldown: 5 * time.Second,
		Logger:          logging.NewLogger(logging.LogError, io.Discard),
	}
	params, _ := json.Marshal(MCPToolsCallParams{Name: "skeptic_daemon_trigger_scan"})
	if _, err := HandleMCPToolsCall(params, state); err != nil {
		t.Fatalf("first trigger should succeed: %v", err)
	}
	if _, err := HandleMCPToolsCall(params, state); err == nil {
		t.Fatal("second trigger within cooldown should fail")
	}
}

func TestMCPScanRepoNotBlockedByTriggerCooldown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "scan scheduled"})
	}))
	defer srv.Close()
	client, _ := daemon.NewDaemonAPIClient(srv.URL, "", true)
	tmpDir := t.TempDir()

	state := &MCPServerState{
		DaemonClient:     client,
		AllowTrigger:     true,
		TriggerCooldown:  5 * time.Second,
		AllowedScanRoots: []string{tmpDir},
		Logger:           logging.NewLogger(logging.LogError, io.Discard),
	}

	triggerParams, _ := json.Marshal(MCPToolsCallParams{Name: "skeptic_daemon_trigger_scan"})
	if _, err := HandleMCPToolsCall(triggerParams, state); err != nil {
		t.Fatalf("daemon trigger should succeed: %v", err)
	}

	scanParams, _ := json.Marshal(MCPToolsCallParams{
		Name:      "skeptic_scan_repo",
		Arguments: map[string]any{"repo_path": tmpDir},
	})
	_, err := HandleMCPToolsCall(scanParams, state)
	if err != nil && strings.Contains(err.Error(), "cooldown") {
		t.Fatal("scan_repo must not be blocked by daemon trigger cooldown")
	}
}

func TestMCPIngestApprovalGate(t *testing.T) {
	state := &MCPServerState{
		AllowIngest:           true,
		RequireIngestApproval: true,
		IngestAllowedHosts:    []string{"example.com"},
		RulesOutDir:           t.TempDir(),
		Logger:                logging.NewLogger(logging.LogError, io.Discard),
		RunIngest:             stubRunIngest,
	}
	params, _ := json.Marshal(MCPToolsCallParams{
		Name:      "skeptic_ingest_url_to_rulepack",
		Arguments: map[string]any{"source_url": "https://example.com/intel"},
	})
	result, err := HandleMCPToolsCall(params, state)
	if err != nil {
		t.Fatalf("pending ingest should not error: %v", err)
	}
	content, _ := result["structuredContent"].(map[string]any)
	if content["status"] != "pending_approval" {
		t.Fatalf("expected pending_approval status, got %v", content["status"])
	}
	if state.PendingIngest == nil {
		t.Fatal("PendingIngest should be set")
	}

	approveParams, _ := json.Marshal(MCPToolsCallParams{Name: "skeptic_approve_ingest"})
	_, err = HandleMCPToolsCall(approveParams, &MCPServerState{Logger: logging.NewLogger(logging.LogError, io.Discard)})
	if err == nil {
		t.Fatal("approve with no pending should fail")
	}
}

func TestMCPToolDescriptorsApproval(t *testing.T) {
	tools := MCPToolDescriptors(false, true, true)
	found := false
	for _, tool := range tools {
		if tool["name"] == "skeptic_approve_ingest" {
			found = true
		}
	}
	if !found {
		t.Fatal("approve_ingest tool should be listed when requireApproval is true")
	}
	tools = MCPToolDescriptors(false, true, false)
	for _, tool := range tools {
		if tool["name"] == "skeptic_approve_ingest" {
			t.Fatal("approve_ingest tool should be hidden when requireApproval is false")
		}
	}
}

func TestServeDryRunAuthMode(t *testing.T) {
	if got := daemon.ServeDryRunAuthMode("", "", true); got != "unauthenticated (open)" {
		t.Fatalf("unexpected auth mode: %s", got)
	}
	if got := daemon.ServeDryRunAuthMode("tok", "", false); got != "bearer token (inline)" {
		t.Fatalf("unexpected auth mode: %s", got)
	}
	if got := daemon.ServeDryRunAuthMode("", "/tmp/tok", false); got != "bearer token (file)" {
		t.Fatalf("unexpected auth mode: %s", got)
	}
	if got := daemon.ServeDryRunAuthMode("", "", false); got != "ephemeral (auto-generated)" {
		t.Fatalf("unexpected auth mode: %s", got)
	}
}

func TestAnyToInt(t *testing.T) {
	value, err := AnyToInt("42", 1)
	if err != nil || value != 42 {
		t.Fatalf("AnyToInt string parse failed value=%d err=%v", value, err)
	}
	value, err = AnyToInt(nil, 7)
	if err != nil || value != 7 {
		t.Fatalf("AnyToInt fallback failed value=%d err=%v", value, err)
	}
	if _, err := AnyToInt("abc", 0); err == nil {
		t.Fatalf("expected invalid int to fail")
	}
}

func TestMCPToolSuccessIntegrity(t *testing.T) {
	payload := map[string]any{"hello": "world", "n": float64(42)}
	result := mcpToolSuccess(payload)
	h, ok := result["integrity_sha256"].(string)
	if !ok || h == "" {
		t.Fatalf("expected integrity_sha256 string, got %#v", result["integrity_sha256"])
	}
	if len(h) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h))
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Fatalf("invalid hex character: %q", c)
		}
	}
	text, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(text)
	expected := hex.EncodeToString(sum[:])
	if h != expected {
		t.Fatalf("hash mismatch: got %s want %s", h, expected)
	}
}

func TestMCPNonceEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()
	client, err := daemon.NewDaemonAPIClient(srv.URL, "", true)
	if err != nil {
		t.Fatalf("NewDaemonAPIClient: %v", err)
	}
	params, err := json.Marshal(MCPToolsCallParams{
		Name:      "skeptic_daemon_health",
		Arguments: map[string]any{"_nonce": "abc123"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	result, err := HandleMCPToolsCall(params, &MCPServerState{DaemonClient: client})
	if err != nil {
		t.Fatalf("HandleMCPToolsCall: %v", err)
	}
	if got, _ := result["_nonce"].(string); got != "abc123" {
		t.Fatalf("expected nonce echo, got %#v", result["_nonce"])
	}
}

func TestMCPConcurrentRequests(t *testing.T) {
	clientToSrvR, clientToSrvW := io.Pipe()
	srvToCliR, srvToCliW := io.Pipe()

	state := &MCPServerState{Logger: logging.NewLogger(logging.LogError, io.Discard)}
	serverDone := make(chan int, 1)
	go func() {
		serverDone <- RunMCPServerLoop(context.Background(), clientToSrvR, srvToCliW, state)
	}()

	respCh := make(chan MCPResponse, 10)
	readErr := make(chan error, 1)
	go func() {
		br := bufio.NewReader(srvToCliR)
		for range 10 {
			frame, err := ReadMCPFrame(br)
			if err != nil {
				readErr <- err
				return
			}
			var resp MCPResponse
			if err := json.Unmarshal(frame, &resp); err != nil {
				readErr <- err
				return
			}
			respCh <- resp
		}
	}()

	bw := bufio.NewWriter(clientToSrvW)
	var writeMu sync.Mutex
	var wg sync.WaitGroup
	var writeErrsMu sync.Mutex
	var writeErrs []error
	for id := 1; id <= 10; id++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			method := "initialize"
			if id%2 == 0 {
				method = "tools/list"
			}
			req := MCPRequest{JSONRPC: "2.0", ID: id, Method: method}
			writeMu.Lock()
			err := WriteMCPFrame(bw, req)
			writeMu.Unlock()
			if err != nil {
				writeErrsMu.Lock()
				writeErrs = append(writeErrs, err)
				writeErrsMu.Unlock()
			}
		}(id)
	}
	wg.Wait()
	if len(writeErrs) > 0 {
		t.Fatalf("write errors: %v", writeErrs)
	}

	ids := map[int]struct{}{}
	for i := range 10 {
		select {
		case resp := <-respCh:
			if resp.Error != nil {
				t.Fatalf("unexpected JSON-RPC error: %+v", resp.Error)
			}
			n, ok := jsonNumberToInt(resp.ID)
			if !ok {
				t.Fatalf("unexpected response id type %T value %#v", resp.ID, resp.ID)
			}
			ids[n] = struct{}{}
		case err := <-readErr:
			t.Fatalf("reader failed at response %d: %v", i, err)
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for MCP responses")
		}
	}
	select {
	case err := <-readErr:
		t.Fatalf("unexpected reader error after 10 responses: %v", err)
	default:
	}
	for want := 1; want <= 10; want++ {
		if _, ok := ids[want]; !ok {
			t.Fatalf("missing response for id %d (have %v)", want, ids)
		}
	}

	_ = clientToSrvW.Close()
	select {
	case code := <-serverDone:
		if code != 0 {
			t.Fatalf("server exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not exit after stdin closed")
	}
}

func jsonNumberToInt(id any) (int, bool) {
	switch v := id.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}

func TestMCPScanTimeout(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	resolvedRepo, err := filepath.EvalSymlinks(absRepo)
	if err != nil {
		t.Fatalf("symlinks: %v", err)
	}

	runScan := func(ctx context.Context, _ []string, _ io.Writer, _ io.Writer) int {
		<-ctx.Done()
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	_, err = MCPScanRepo(ctx, map[string]any{
		"repo_path":    repoDir,
		"require_git":  false,
		"max_files":    10,
		"max_findings": 10,
	}, &MCPServerState{
		AllowedScanRoots: []string{resolvedRepo},
		RunScan:          runScan,
		TriggerCooldown:  0,
	})
	if err == nil {
		t.Fatal("expected error when scan context times out")
	}
	if !strings.Contains(err.Error(), "exit code") {
		t.Fatalf("expected scan failure message, got: %v", err)
	}
}

func TestMCPDaemonStatusTool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"listen_address": "127.0.0.1:7788",
				"running":        false,
				"scan_count":     3,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	client, err := daemon.NewDaemonAPIClient(srv.URL, "", true)
	if err != nil {
		t.Fatalf("NewDaemonAPIClient: %v", err)
	}
	params, err := json.Marshal(MCPToolsCallParams{Name: "skeptic_daemon_status"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	result, err := HandleMCPToolsCall(params, &MCPServerState{DaemonClient: client})
	if err != nil {
		t.Fatalf("HandleMCPToolsCall: %v", err)
	}
	sc, _ := result["structuredContent"].(map[string]any)
	if sc["listen_address"] != "127.0.0.1:7788" {
		t.Fatalf("unexpected status result: %#v", sc)
	}
}

func TestMCPDaemonReportTool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/report" && r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"scanned_files": 42,
				"findings":      []any{},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	client, err := daemon.NewDaemonAPIClient(srv.URL, "", true)
	if err != nil {
		t.Fatalf("NewDaemonAPIClient: %v", err)
	}
	params, err := json.Marshal(MCPToolsCallParams{Name: "skeptic_daemon_report"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	result, err := HandleMCPToolsCall(params, &MCPServerState{DaemonClient: client})
	if err != nil {
		t.Fatalf("HandleMCPToolsCall: %v", err)
	}
	sc, _ := result["structuredContent"].(map[string]any)
	if sc["scanned_files"] == nil {
		t.Fatalf("unexpected report result: %#v", sc)
	}
}

func TestMCPDaemonStatusToolNoDaemon(t *testing.T) {
	params, _ := json.Marshal(MCPToolsCallParams{Name: "skeptic_daemon_status"})
	_, err := HandleMCPToolsCall(params, &MCPServerState{})
	if err == nil {
		t.Fatal("expected error when DaemonClient is nil")
	}
}

func TestMCPMalformedRequestWithIDReturnsError(t *testing.T) {
	input := "{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":123}\n"
	var out bytes.Buffer
	state := &MCPServerState{Logger: logging.NewLogger(logging.LogError, io.Discard)}
	code := RunMCPServerLoop(context.Background(), strings.NewReader(input), &out, state)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	var resp MCPResponse
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("expected valid JSON-RPC error response, got parse error: %v\nraw: %s", err, out.String())
	}
	if resp.Error == nil {
		t.Fatal("expected JSON-RPC error in response")
	}
	if resp.Error.Code != -32600 {
		t.Fatalf("expected error code -32600, got %d", resp.Error.Code)
	}
	idFloat, ok := resp.ID.(float64)
	if !ok || int(idFloat) != 42 {
		t.Fatalf("expected response id=42, got %v (%T)", resp.ID, resp.ID)
	}
}

func TestMCPMalformedRequestWithoutIDSilent(t *testing.T) {
	input := "{\"jsonrpc\":\"2.0\"}\n"
	var out bytes.Buffer
	state := &MCPServerState{Logger: logging.NewLogger(logging.LogError, io.Discard)}
	code := RunMCPServerLoop(context.Background(), strings.NewReader(input), &out, state)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Fatalf("expected no output for malformed request without id, got: %s", out.String())
	}
}

func TestMCPConnectionDrop(t *testing.T) {
	clientToSrvR, clientToSrvW := io.Pipe()
	_, srvToCliW := io.Pipe()

	state := &MCPServerState{Logger: logging.NewLogger(logging.LogError, io.Discard)}
	done := make(chan int, 1)
	go func() {
		done <- RunMCPServerLoop(context.Background(), clientToSrvR, srvToCliW, state)
	}()

	if _, err := io.WriteString(clientToSrvW, "{\"jsonrpc\":\"2.0\"\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := clientToSrvW.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case code := <-done:
		if code != 0 && code != 1 {
			t.Fatalf("unexpected exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server hung after broken connection")
	}
}

func TestResolveMCPAllowedScanRoots(t *testing.T) {
	t.Run("empty returns nil (unrestricted)", func(t *testing.T) {
		roots, err := ResolveMCPAllowedScanRoots("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if roots != nil {
			t.Fatalf("expected nil (unrestricted), got %v", roots)
		}
	})

	t.Run("comma-separated paths", func(t *testing.T) {
		d1 := t.TempDir()
		d2 := t.TempDir()
		roots, err := ResolveMCPAllowedScanRoots(d1 + "," + d2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(roots) != 2 {
			t.Fatalf("expected 2 roots, got %d", len(roots))
		}
	})

	t.Run("whitespace and empty entries", func(t *testing.T) {
		d1 := t.TempDir()
		roots, err := ResolveMCPAllowedScanRoots("  " + d1 + " , , ")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(roots) != 1 {
			t.Fatalf("expected 1 root, got %d: %v", len(roots), roots)
		}
	})
}

func TestParseMCPIngestAllowedHosts(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty returns nil", "", 0},
		{"whitespace only", "   ", 0},
		{"single host", "example.com", 1},
		{"multiple hosts", "example.com, GitHub.COM, test.org", 3},
		{"trailing commas", "a.com,,b.com,", 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseMCPIngestAllowedHosts(tc.input)
			if tc.want == 0 && got != nil {
				t.Errorf("expected nil, got %v", got)
			} else if len(got) != tc.want {
				t.Errorf("expected %d hosts, got %d: %v", tc.want, len(got), got)
			}
			for _, h := range got {
				if h != strings.ToLower(h) {
					t.Errorf("host should be lowercased: %q", h)
				}
			}
		})
	}
}

func TestPathUnderAllowedScanRoots(t *testing.T) {
	tests := []struct {
		name     string
		resolved string
		allowed  []string
		want     bool
	}{
		{"exact match", "/home/user/repo", []string{"/home/user/repo"}, true},
		{"subdirectory", "/home/user/repo/src/main.go", []string{"/home/user/repo"}, true},
		{"outside root", "/home/other/repo", []string{"/home/user/repo"}, false},
		{"prefix but not subdir", "/home/user/repo-extra", []string{"/home/user/repo"}, false},
		{"empty allowed means unrestricted", "/home/user/repo", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PathUnderAllowedScanRoots(tc.resolved, tc.allowed); got != tc.want {
				t.Errorf("PathUnderAllowedScanRoots(%q, %v) = %v, want %v", tc.resolved, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestBuildTrustAssessment(t *testing.T) {
	t.Run("no findings", func(t *testing.T) {
		report := model.Report{}
		ta := BuildTrustAssessment(report)
		verdict, _ := ta["verdict"].(string)
		if verdict != "no_issues_found" {
			t.Errorf("expected no_issues_found, got %q", verdict)
		}
	})

	t.Run("critical definitive finding triggers action_required", func(t *testing.T) {
		report := model.Report{
			Findings: []model.Finding{
				{
					RuleID:          "CI-PRT-001",
					Severity:        model.SeverityCritical,
					ConfidenceClass: model.ConfidenceDefinitive,
					Category:        "ci",
				},
			},
			FindingsByConfidence: map[string]int{
				string(model.ConfidenceDefinitive): 1,
			},
		}
		ta := BuildTrustAssessment(report)
		verdict, _ := ta["verdict"].(string)
		if verdict != "action_required" {
			t.Errorf("expected action_required, got %q", verdict)
		}
	})

	t.Run("high definitive finding triggers review_advised", func(t *testing.T) {
		report := model.Report{
			Findings: []model.Finding{
				{
					RuleID:          "CI-PRT-002",
					Severity:        model.SeverityHigh,
					ConfidenceClass: model.ConfidenceDefinitive,
					Category:        "ci",
				},
			},
			FindingsByConfidence: map[string]int{
				string(model.ConfidenceDefinitive): 1,
			},
		}
		ta := BuildTrustAssessment(report)
		verdict, _ := ta["verdict"].(string)
		if verdict != "review_advised" {
			t.Errorf("expected review_advised, got %q", verdict)
		}
	})

	t.Run("IR mode action_required without gate eligibility", func(t *testing.T) {
		report := model.Report{
			Mode: model.ScanModeIR,
			Findings: []model.Finding{
				{
					RuleID:          "ATK-PER-001",
					Severity:        model.SeverityCritical,
					ConfidenceClass: model.ConfidenceDefinitive,
					Category:        "attack-tactics",
				},
			},
			FindingsByConfidence: map[string]int{
				string(model.ConfidenceDefinitive): 1,
			},
		}
		ta := BuildTrustAssessment(report)
		verdict, _ := ta["verdict"].(string)
		if verdict != "action_required" {
			t.Errorf("IR mode: expected action_required for definitive critical (non-gate-eligible), got %q", verdict)
		}
	})

	t.Run("developer mode non-gate-eligible yields no_issues_found", func(t *testing.T) {
		report := model.Report{
			Mode: model.ScanModeDeveloper,
			Findings: []model.Finding{
				{
					RuleID:          "ATK-PER-001",
					Severity:        model.SeverityCritical,
					ConfidenceClass: model.ConfidenceDefinitive,
					Category:        "attack-tactics",
				},
			},
			FindingsByConfidence: map[string]int{
				string(model.ConfidenceDefinitive): 1,
			},
		}
		ta := BuildTrustAssessment(report)
		verdict, _ := ta["verdict"].(string)
		if verdict != "no_issues_found" {
			t.Errorf("developer mode: expected no_issues_found for non-gate-eligible, got %q", verdict)
		}
	})

	t.Run("IR mode review_advised for high definitive", func(t *testing.T) {
		report := model.Report{
			Mode: model.ScanModeIR,
			Findings: []model.Finding{
				{
					RuleID:          "BHV-SC-001",
					Severity:        model.SeverityHigh,
					ConfidenceClass: model.ConfidenceDefinitive,
					Category:        "behavioral",
				},
			},
			FindingsByConfidence: map[string]int{
				string(model.ConfidenceDefinitive): 1,
			},
		}
		ta := BuildTrustAssessment(report)
		verdict, _ := ta["verdict"].(string)
		if verdict != "review_advised" {
			t.Errorf("IR mode: expected review_advised for high definitive, got %q", verdict)
		}
	})

	t.Run("risk_areas populated", func(t *testing.T) {
		report := model.Report{
			Findings: []model.Finding{
				{RuleID: "TEST-001", Category: "supply-chain", Severity: model.SeverityHigh, ConfidenceClass: model.ConfidenceDefinitive},
				{RuleID: "TEST-002", Category: "supply-chain", Severity: model.SeverityMedium, ConfidenceClass: model.ConfidenceHeuristic},
			},
			FindingsByConfidence: map[string]int{string(model.ConfidenceDefinitive): 1, string(model.ConfidenceHeuristic): 1},
		}
		ta := BuildTrustAssessment(report)
		areas, ok := ta["risk_areas"].([]map[string]any)
		if !ok || len(areas) == 0 {
			t.Error("expected non-empty risk_areas")
		}
	})
}

func TestHandleMCPResourcesList(t *testing.T) {
	result := HandleMCPResourcesList()
	resources, ok := result["resources"].([]map[string]any)
	if !ok {
		t.Fatal("expected resources key")
	}
	if len(resources) != 4 {
		t.Errorf("expected 4 resources, got %d", len(resources))
	}
	uris := make(map[string]bool)
	for _, r := range resources {
		uri, _ := r["uri"].(string)
		uris[uri] = true
	}
	for _, expected := range []string{"skeptic://rules/builtin", "skeptic://rules/external", "skeptic://report/latest", "skeptic://config/active"} {
		if !uris[expected] {
			t.Errorf("missing expected resource URI %q", expected)
		}
	}
}

func TestHandleMCPResourcesRead(t *testing.T) {
	state := &MCPServerState{
		Logger:             logging.NewLogger(logging.LogError, io.Discard),
		AllowTrigger:       true,
		AllowIngest:        false,
		TriggerCooldown:    30 * time.Second,
		AllowedScanRoots:   []string{"/home/user/repos"},
		IngestAllowedHosts: nil,
		RulesOutDir:        "/tmp/rules",
		DefaultRules: func() []model.Rule {
			return []model.Rule{
				{ID: "TEST-001", Title: "Test Rule", Severity: model.SeverityHigh, Category: "test"},
			}
		},
	}

	t.Run("builtin rules", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"uri": "skeptic://rules/builtin"})
		result, err := HandleMCPResourcesRead(json.RawMessage(params), state)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		contents, ok := result["contents"].([]map[string]any)
		if !ok || len(contents) == 0 {
			t.Fatal("expected contents in response")
		}
		text, _ := contents[0]["text"].(string)
		if !strings.Contains(text, "TEST-001") {
			t.Errorf("expected builtin rules to contain TEST-001, got %s", text)
		}
	})

	t.Run("external rules", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"uri": "skeptic://rules/external"})
		result, err := HandleMCPResourcesRead(json.RawMessage(params), state)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		contents, ok := result["contents"].([]map[string]any)
		if !ok || len(contents) == 0 {
			t.Fatal("expected contents")
		}
	})

	t.Run("latest report without daemon", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"uri": "skeptic://report/latest"})
		result, err := HandleMCPResourcesRead(json.RawMessage(params), state)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		contents, ok := result["contents"].([]map[string]any)
		if !ok || len(contents) == 0 {
			t.Fatal("expected contents")
		}
		text, _ := contents[0]["text"].(string)
		if !strings.Contains(text, "no_report_available") {
			t.Errorf("expected no_report_available, got %s", text)
		}
	})

	t.Run("config active", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"uri": "skeptic://config/active"})
		result, err := HandleMCPResourcesRead(json.RawMessage(params), state)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		contents, ok := result["contents"].([]map[string]any)
		if !ok || len(contents) == 0 {
			t.Fatal("expected contents")
		}
		text, _ := contents[0]["text"].(string)
		if !strings.Contains(text, "allow_trigger") {
			t.Errorf("expected config to contain allow_trigger, got %s", text)
		}
		if !strings.Contains(text, "builtin_rule_count") {
			t.Errorf("expected config to contain builtin_rule_count, got %s", text)
		}
		var configData map[string]any
		if err := json.Unmarshal([]byte(text), &configData); err != nil {
			t.Fatalf("config resource is not valid JSON: %v", err)
		}
		if configData["allow_trigger"] != true {
			t.Errorf("expected allow_trigger=true, got %v", configData["allow_trigger"])
		}
		if configData["daemon_connected"] != false {
			t.Errorf("expected daemon_connected=false, got %v", configData["daemon_connected"])
		}
	})

	t.Run("unknown URI returns error", func(t *testing.T) {
		params, _ := json.Marshal(map[string]string{"uri": "skeptic://nonexistent"})
		_, err := HandleMCPResourcesRead(json.RawMessage(params), state)
		if err == nil {
			t.Error("expected error for unknown URI")
		}
	})

	t.Run("invalid params", func(t *testing.T) {
		_, err := HandleMCPResourcesRead(json.RawMessage(`not json`), state)
		if err == nil {
			t.Error("expected error for invalid params")
		}
	})
}

func TestMCPDaemonMetricsTool(t *testing.T) {
	metricsBody := `# HELP skeptic_scans_total Total scans
skeptic_scans_total 5
skeptic_findings_total 12
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(metricsBody))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	client, err := daemon.NewDaemonAPIClient(srv.URL, "", true)
	if err != nil {
		t.Fatalf("NewDaemonAPIClient: %v", err)
	}
	params, err := json.Marshal(MCPToolsCallParams{Name: "skeptic_daemon_metrics"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	result, err := HandleMCPToolsCall(params, &MCPServerState{DaemonClient: client})
	if err != nil {
		t.Fatalf("HandleMCPToolsCall: %v", err)
	}
	sc, _ := result["structuredContent"].(map[string]any)
	if sc["format"] != "prometheus" {
		t.Fatalf("expected format=prometheus, got %v", sc["format"])
	}
	metrics, _ := sc["metrics"].(string)
	if !strings.Contains(metrics, "skeptic_scans_total") {
		t.Fatalf("expected metrics to contain skeptic_scans_total, got %s", metrics)
	}
}

func TestMCPDaemonMetricsToolNoDaemon(t *testing.T) {
	params, _ := json.Marshal(MCPToolsCallParams{Name: "skeptic_daemon_metrics"})
	_, err := HandleMCPToolsCall(params, &MCPServerState{})
	if err == nil {
		t.Fatal("expected error when DaemonClient is nil")
	}
}

func TestMCPToolDescriptorsIncludeMetrics(t *testing.T) {
	tools := MCPToolDescriptors(false, false, false)
	found := false
	for _, tool := range tools {
		if tool["name"] == "skeptic_daemon_metrics" {
			found = true
		}
	}
	if !found {
		t.Fatal("skeptic_daemon_metrics should always be present in tool descriptors")
	}
}

func TestMCPScanRepoUnrestrictedRoots(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	// AllowedScanRoots is nil — unrestricted mode; any valid git repo is accepted.
	result, err := MCPScanRepo(context.Background(), map[string]any{
		"repo_path": repoDir,
	}, &MCPServerState{AllowedScanRoots: nil, RunScan: stubRunScan})
	if err != nil {
		t.Fatalf("MCPScanRepo with nil roots should succeed: %v", err)
	}
	if result["repo_path"] == "" {
		t.Error("expected repo_path in result")
	}
}

func TestMCPScanRepoAutoDiscoverMCPAlwaysDisabled(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	absRepo, _ := filepath.Abs(repoDir)
	resolvedRepo, _ := filepath.EvalSymlinks(absRepo)

	var capturedArgs []string
	captureScan := func(_ context.Context, args []string, stdout io.Writer, _ io.Writer) int {
		capturedArgs = args
		_ = json.NewEncoder(stdout).Encode(model.Report{ScannedFiles: 1})
		return 0
	}

	// Use the "dev" preset, which normally sets auto-discover-mcp=true.
	// MCPScanRepo must override this to false to prevent host IDE environment pollution.
	_, err := MCPScanRepo(context.Background(), map[string]any{
		"repo_path": repoDir,
		"preset":    "dev",
	}, &MCPServerState{AllowedScanRoots: []string{resolvedRepo}, RunScan: captureScan})
	if err != nil {
		t.Fatalf("MCPScanRepo failed: %v", err)
	}

	argsStr := strings.Join(capturedArgs, " ")
	if !strings.Contains(argsStr, "--auto-discover-mcp=false") {
		t.Errorf("expected --auto-discover-mcp=false in scan args; got: %s", argsStr)
	}
}

func TestMCPScanRepoParams(t *testing.T) {
	gitRepoFixture := func(t *testing.T) (repoDir, allowedRoot string) {
		t.Helper()
		repoDir = t.TempDir()
		if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
			t.Fatalf("mkdir .git: %v", err)
		}
		absRepo, err := filepath.Abs(repoDir)
		if err != nil {
			t.Fatalf("abs: %v", err)
		}
		resolvedRepo, err := filepath.EvalSymlinks(absRepo)
		if err != nil {
			t.Fatalf("eval symlinks: %v", err)
		}
		return repoDir, resolvedRepo
	}

	t.Run("include_rules", func(t *testing.T) {
		repoDir, allowedRoot := gitRepoFixture(t)
		result, err := MCPScanRepo(context.Background(), map[string]any{
			"repo_path":     repoDir,
			"include_rules": "CI-BUILD-*",
		}, &MCPServerState{AllowedScanRoots: []string{allowedRoot}, RunScan: stubRunScan})
		if err != nil {
			t.Fatalf("MCPScanRepo: %v", err)
		}
		if _, ok := result["findings_total"]; !ok {
			t.Fatalf("expected findings_total in result, got keys: %#v", resultKeys(result))
		}
	})

	t.Run("exclude_rules", func(t *testing.T) {
		repoDir, allowedRoot := gitRepoFixture(t)
		result, err := MCPScanRepo(context.Background(), map[string]any{
			"repo_path":     repoDir,
			"exclude_rules": "AGT-*",
		}, &MCPServerState{AllowedScanRoots: []string{allowedRoot}, RunScan: stubRunScan})
		if err != nil {
			t.Fatalf("MCPScanRepo: %v", err)
		}
		if _, ok := result["findings_total"]; !ok {
			t.Fatalf("expected findings_total in result, got keys: %#v", resultKeys(result))
		}
	})

	t.Run("workers_zero", func(t *testing.T) {
		repoDir, allowedRoot := gitRepoFixture(t)
		var capturedArgs []string
		runScan := func(_ context.Context, args []string, stdout io.Writer, _ io.Writer) int {
			capturedArgs = append([]string(nil), args...)
			_ = json.NewEncoder(stdout).Encode(model.Report{ScannedFiles: 1})
			return 0
		}
		_, err := MCPScanRepo(context.Background(), map[string]any{
			"repo_path": repoDir,
			"workers":   0,
		}, &MCPServerState{AllowedScanRoots: []string{allowedRoot}, RunScan: runScan})
		if err != nil {
			t.Fatalf("MCPScanRepo: %v", err)
		}
		argsStr := strings.Join(capturedArgs, " ")
		if strings.Contains(argsStr, "--workers") {
			t.Fatalf("expected workers=0 to omit --workers, got: %s", argsStr)
		}
	})

	t.Run("invalid_preset", func(t *testing.T) {
		repoDir, allowedRoot := gitRepoFixture(t)
		runScan := func(_ context.Context, args []string, _ io.Writer, stderr io.Writer) int {
			for i := 0; i < len(args)-1; i++ {
				if args[i] == "--preset" && args[i+1] == "nonexistent_preset" {
					_, _ = fmt.Fprintln(stderr, "invalid preset: nonexistent_preset")
					return 1
				}
			}
			return stubRunScan(context.Background(), args, io.Discard, stderr)
		}
		_, err := MCPScanRepo(context.Background(), map[string]any{
			"repo_path": repoDir,
			"preset":    "nonexistent_preset",
		}, &MCPServerState{AllowedScanRoots: []string{allowedRoot}, RunScan: runScan})
		if err == nil {
			t.Fatal("expected error when scan exits non-zero for invalid preset")
		}
	})

	t.Run("baseline_nonexistent_path", func(t *testing.T) {
		repoDir, allowedRoot := gitRepoFixture(t)
		baselinePath := "/tmp/nonexistent_baseline_12345.json"
		_, err := MCPScanRepo(context.Background(), map[string]any{
			"repo_path": repoDir,
			"baseline":  baselinePath,
			"diff_only": true,
		}, &MCPServerState{AllowedScanRoots: []string{allowedRoot}, RunScan: stubRunScan})
		if err != nil {
			t.Fatalf("MCPScanRepo should handle missing baseline without failing parse: %v", err)
		}
	})
}

func resultKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TestMCPScanRepoWithPreset(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git failed: %v", err)
	}
	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	resolvedRepo, err := filepath.EvalSymlinks(absRepo)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}

	var capturedArgs []string
	captureScan := func(_ context.Context, args []string, stdout io.Writer, _ io.Writer) int {
		capturedArgs = args
		report := model.Report{ScannedFiles: 1}
		_ = json.NewEncoder(stdout).Encode(report)
		return 0
	}

	_, err = MCPScanRepo(context.Background(), map[string]any{
		"repo_path":     repoDir,
		"preset":        "hunt",
		"profile":       "container",
		"include_rules": "CI-,AGT-",
		"exclude_rules": "BHV-",
		"incremental":   true,
		"workers":       4,
	}, &MCPServerState{AllowedScanRoots: []string{resolvedRepo}, RunScan: captureScan})
	if err != nil {
		t.Fatalf("MCPScanRepo failed: %v", err)
	}

	argsStr := strings.Join(capturedArgs, " ")
	for _, want := range []string{"--preset hunt", "--profile container", "--include-rules CI-,AGT-", "--exclude-rules BHV-", "--incremental", "--workers 4"} {
		if !strings.Contains(argsStr, want) {
			t.Errorf("expected args to contain %q, got: %s", want, argsStr)
		}
	}
}

func TestMCPScanRepoResponseFields(t *testing.T) {
	repoDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git failed: %v", err)
	}
	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	resolvedRepo, err := filepath.EvalSymlinks(absRepo)
	if err != nil {
		t.Fatalf("eval symlinks: %v", err)
	}

	scanWithRiskScore := func(_ context.Context, _ []string, stdout io.Writer, _ io.Writer) int {
		report := model.Report{
			ScannedFiles: 1,
			RiskScore:    42,
			Findings: []model.Finding{
				{RuleID: "TEST-001", Severity: model.SeverityHigh, Title: "Test"},
			},
			FindingsBySeverity: map[string]int{"high": 1},
		}
		_ = json.NewEncoder(stdout).Encode(report)
		return 0
	}

	result, err := MCPScanRepo(context.Background(), map[string]any{
		"repo_path": repoDir,
		"mode":      "ir",
	}, &MCPServerState{AllowedScanRoots: []string{resolvedRepo}, RunScan: scanWithRiskScore})
	if err != nil {
		t.Fatalf("MCPScanRepo failed: %v", err)
	}

	if result["mode"] != "ir" {
		t.Errorf("expected mode=ir, got %v", result["mode"])
	}
	riskScore, ok := result["risk_score"].(float64)
	if !ok {
		riskScoreInt, okInt := result["risk_score"].(int)
		if !okInt {
			t.Fatalf("expected risk_score in response, got %T: %v", result["risk_score"], result["risk_score"])
		}
		riskScore = float64(riskScoreInt)
	}
	if riskScore != 42 {
		t.Errorf("expected risk_score=42, got %v", riskScore)
	}
}

func TestMCPResourcesListIncludesConfig(t *testing.T) {
	result := HandleMCPResourcesList()
	resources, ok := result["resources"].([]map[string]any)
	if !ok {
		t.Fatal("expected resources key")
	}
	if len(resources) != 4 {
		t.Errorf("expected 4 resources, got %d", len(resources))
	}
	found := false
	for _, r := range resources {
		if r["uri"] == "skeptic://config/active" {
			found = true
		}
	}
	if !found {
		t.Error("expected skeptic://config/active resource")
	}
}

func TestMCPInitializeDeclaresResources(t *testing.T) {
	req := MCPRequest{JSONRPC: "2.0", ID: 1, Method: "initialize"}
	resp, shouldRespond := HandleMCPRequest(req, &MCPServerState{})
	if !shouldRespond {
		t.Fatal("initialize should return a response")
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type: %T", resp.Result)
	}
	caps, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatal("expected capabilities in result")
	}
	if _, ok := caps["resources"]; !ok {
		t.Error("expected resources capability to be declared")
	}
	if _, ok := caps["tools"]; !ok {
		t.Error("expected tools capability to be declared")
	}
}

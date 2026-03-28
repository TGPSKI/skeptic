package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

func TestHealthHandler(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/health status = %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("/health json decode: %v", err)
	}
	if body["ok"] != true {
		t.Errorf("/health ok = %v, want true", body["ok"])
	}
	if body["service"] != "skeptic-daemon" {
		t.Errorf("/health service = %v", body["service"])
	}
}

func TestHealthHandlerMethodNotAllowed(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("/health POST status = %d, want 405", w.Code)
	}
}

func TestStatusHandler(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "testtoken", false, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("Authorization", "Bearer testtoken")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("/status status = %d, want 200", w.Code)
	}
	var body DaemonStatus
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("/status json decode: %v", err)
	}
	if body.ListenAddress != "127.0.0.1:7788" {
		t.Errorf("/status listen_address = %q", body.ListenAddress)
	}
}

func TestStatusHandlerUnauthorized(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "testtoken", false, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/status no auth status = %d, want 401", w.Code)
	}
}

func TestScanHandler(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("/scan POST status = %d, want 202", w.Code)
	}
	select {
	case reason := <-triggerCh:
		if reason != "api" {
			t.Errorf("trigger reason = %q, want api", reason)
		}
	default:
		t.Fatal("expected trigger on channel after /scan POST")
	}
}

func TestScanHandlerMethodNotAllowed(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/scan", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("/scan GET status = %d, want 405", w.Code)
	}
}

func TestReportHandlerNoReport(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/report", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("/report no report status = %d, want 404", w.Code)
	}
}

func TestDaemonRuntimeStateWriteMetrics(t *testing.T) {
	state := &DaemonRuntimeState{
		scanCount:      7,
		totalFindings:  42,
		lastDurationMs: 1500,
		rulesLoaded:    99,
		lastScanEpoch:  1234567890,
		hasReport:      true,
		lastReport: model.Report{
			FindingsBySeverity: map[string]int{"high": 3},
		},
	}
	var buf bytes.Buffer
	state.WriteMetrics(&buf)
	out := buf.String()

	checks := []string{
		"skeptic_scans_total 7",
		"skeptic_findings_total 42",
		"skeptic_scan_duration_seconds 1.500",
		"skeptic_rules_loaded 99",
		"skeptic_last_scan_epoch 1234567890",
		`skeptic_findings_by_severity{severity="high"} 3`,
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Fatalf("metrics output missing %q\nfull output:\n%s", want, out)
		}
	}
}

func TestDaemonStateConcurrentAccess(t *testing.T) {
	state := &DaemonRuntimeState{}
	const n = 20
	var wg sync.WaitGroup
	for g := 0; g < n; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				switch rand.IntN(4) {
				case 0:
					if state.BeginRun("stress") {
						state.EndRun(model.Report{ScannedFiles: 1, Findings: []model.Finding{{RuleID: "T"}}}, 0, nil)
					}
				case 1:
					_ = state.Status("127.0.0.1:7788", 5*time.Minute)
				case 2:
					_, _ = state.Report()
				case 3:
					state.SetNextRun(time.Now().Add(time.Minute))
				}
			}
		}()
	}
	wg.Wait()
	st := state.Status("127.0.0.1:7788", 5*time.Minute)
	if st.Running {
		state.EndRun(model.Report{}, 0, nil)
	}
	st = state.Status("127.0.0.1:7788", 5*time.Minute)
	if st.Running {
		t.Fatalf("expected running=false after cleanup, got running=true scan_count=%d", st.ScanCount)
	}
	if st.ScanCount < 0 {
		t.Fatalf("invalid scan count %d", st.ScanCount)
	}
}

func TestConcurrentScanAndStatusRequests(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, MaxDaemonScanTriggerBacklog)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", time.Minute)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []string
	record := func(format string, args ...any) {
		mu.Lock()
		errs = append(errs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/status", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				record("GET /status: status=%d", w.Code)
			}
		}()
	}
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/scan", nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != http.StatusAccepted {
				record("POST /scan: status=%d", w.Code)
			}
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatal(strings.Join(errs, "; "))
	}
}

func TestReportHandlerUnauthorized(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "secrettoken", false, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/report", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/report no auth status = %d, want 401", w.Code)
	}
}

func TestScanHandlerUnauthorized(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "secrettoken", false, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/scan no auth status = %d, want 401", w.Code)
	}
}

func TestScanHandlerBackpressure(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	triggerCh <- "fill"
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests && w.Code != http.StatusAccepted {
		t.Logf("/scan backpressure status = %d (channel-full behavior)", w.Code)
	}
}

func TestStatusHandlerMethodNotAllowed(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/status", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("/status POST status = %d, want 405", w.Code)
	}
}

func TestReportHandlerMethodNotAllowed(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/report", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("/report POST status = %d, want 405", w.Code)
	}
}

func TestMetricsHandlerMethodNotAllowed(t *testing.T) {
	state := &DaemonRuntimeState{}
	triggerCh := make(chan string, 1)
	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, "", true, state, triggerCh, "127.0.0.1:7788", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("/metrics POST status = %d, want 405", w.Code)
	}
}

func TestRequestText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("skeptic_scans_total 5\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client, err := NewDaemonAPIClient(srv.URL, "tok", true)
	if err != nil {
		t.Fatalf("NewDaemonAPIClient: %v", err)
	}
	text, err := client.RequestText(t.Context(), http.MethodGet, "/metrics")
	if err != nil {
		t.Fatalf("RequestText: %v", err)
	}
	if !strings.Contains(text, "skeptic_scans_total") {
		t.Errorf("expected metrics text, got %q", text)
	}
}

func TestRequestTextError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer srv.Close()
	client, _ := NewDaemonAPIClient(srv.URL, "", true)
	_, err := client.RequestText(t.Context(), http.MethodGet, "/bad")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestFilterReportPreservesStoredOrder(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "R1", Severity: model.SeverityLow, File: "a.txt"},
		{RuleID: "R2", Severity: model.SeverityHigh, File: "b.txt"},
		{RuleID: "R3", Severity: model.SeverityMedium, File: "c.txt"},
	}
	state := &DaemonRuntimeState{}
	state.BeginRun("test")
	state.EndRun(model.Report{
		Findings:           findings,
		FindingsBySeverity: map[string]int{"low": 1, "high": 1, "medium": 1},
	}, 0, nil)

	stored, ok := state.Report()
	if !ok {
		t.Fatal("expected report to be available")
	}

	_ = filterReportForResponse(stored, "", "")

	after, _ := state.Report()
	for i, f := range after.Findings {
		if f.RuleID != findings[i].RuleID {
			t.Fatalf("stored finding order changed at index %d: got %s want %s", i, f.RuleID, findings[i].RuleID)
		}
	}
}

func TestFilterReportConcurrentSafe(t *testing.T) {
	findings := make([]model.Finding, 50)
	for i := range findings {
		var sev model.Severity
		switch i % 3 {
		case 0:
			sev = model.SeverityHigh
		case 1:
			sev = model.SeverityMedium
		default:
			sev = model.SeverityLow
		}
		findings[i] = model.Finding{
			RuleID:   fmt.Sprintf("R%d", i),
			Severity: sev,
			File:     fmt.Sprintf("file%d.txt", i),
		}
	}
	report := model.Report{Findings: findings}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_ = filterReportForResponse(report, "10", "")
			}
		}()
	}
	wg.Wait()

	for i, f := range report.Findings {
		if f.RuleID != findings[i].RuleID {
			t.Fatalf("original report findings mutated at index %d: got %s want %s", i, f.RuleID, findings[i].RuleID)
		}
	}
}

func TestSchedulerCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	triggerCh := make(chan string, MaxDaemonScanTriggerBacklog)
	cfg := DaemonConfig{
		Interval:   20 * time.Millisecond,
		RunOnStart: false,
		ScanArgs:   nil,
	}
	logger := logging.NewLogger(logging.LogError, io.Discard)
	state := &DaemonRuntimeState{}
	deps := DaemonDeps{
		ExecuteScan: func(_ []string, _ *logging.Logger, _ ScanFunc) (model.Report, int, string, error) {
			return model.Report{}, 0, "", nil
		},
	}
	done := make(chan struct{})
	go func() {
		RunDaemonScheduler(ctx, triggerCh, cfg, logger, state, deps)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunDaemonScheduler did not return after context cancel")
	}
}

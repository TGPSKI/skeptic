// Package daemon implements the skeptic HTTP daemon: scheduled scans, optional
// filesystem watch, health/status/report/metrics endpoints, and graceful shutdown.
package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/TGPSKI/skeptic/internal/config"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

// Daemon HTTP server and scheduler timing defaults.
const (
	DaemonHTTPReadTimeout       = 10 * time.Second
	DaemonHTTPWriteTimeout      = 30 * time.Second
	DaemonHTTPIdleTimeout       = 60 * time.Second
	DaemonSchedulerStopWait     = 8 * time.Second
	DefaultDaemonShutdownWait   = 5 * time.Second
	MaxDaemonScanTriggerBacklog = 1
)

// ErrServeHelpRequested is returned by ParseServeFlags when the user passed -h/--help.
var ErrServeHelpRequested = errors.New("serve: help requested")

// errServeFlagParse marks FlagSet.Parse failures after usage was already written to stderr.
var errServeFlagParse = errors.New("serve: flag parse")

// ScanFunc performs a scan given compiled rules and options. The CLI wires this to
// the main scan pipeline to avoid import cycles with package main.
type ScanFunc func(ctx context.Context, rules []model.Rule, opts model.ScanOptions) (model.Report, error)

// GlobalFlagOverrides carries global flags extracted by the CLI dispatcher so the
// daemon can apply them to its own logger and forward them to scheduled scans.
type GlobalFlagOverrides struct {
	Verbosity int
	Quiet     bool
	Config    string
	LogFile   string
}

// SystemDaemonConfig holds the subset of system config relevant to the daemon.
// Populated by the CLI layer (which can import internal/config) and passed through DaemonDeps.
type SystemDaemonConfig struct {
	DaemonBind     string
	DaemonTokenDir string
	LogDir         string
}

// DaemonDeps supplies scan execution for the daemon without importing package main.
type DaemonDeps struct {
	Scan ScanFunc
	// ExecuteScan runs a full scan for the given skeptic CLI args (same as a normal
	// `skeptic ...` invocation, minus subcommands). It must call Scan with the
	// resolved rules and options internally.
	ExecuteScan  func(scanArgs []string, logger *logging.Logger, scan ScanFunc) (model.Report, int, string, error)
	RulesLoaded  int
	GlobalFlags  GlobalFlagOverrides
	SystemConfig SystemDaemonConfig
}

// DaemonConfig captures resolved settings for the HTTP daemon after flag parsing.
type DaemonConfig struct {
	BindAddr             string
	Interval             time.Duration
	RunOnStart           bool
	AuthToken            string
	AuthTokenRaw         string
	AuthTokenFile        string
	AllowUnauthenticated bool
	DryRun               bool
	WatchMode            bool
	WatchPaths           string
	Verbosity            int
	Quiet                bool
	LogFilePath          string
	ReportFile           string
	ConfigPath           string
	PprofAddr            string
	ScanArgs             []string

	// visitedFlags tracks which serve flags were explicitly set by the user
	// so that global flag and system config defaults don't override them.
	visitedFlags map[string]struct{}
}

// DaemonStatus captures externally visible daemon state for status APIs.
type DaemonStatus struct {
	ListenAddress string `json:"listen_address"`
	Interval      string `json:"interval"`
	Running       bool   `json:"running"`
	LastRunAt     string `json:"last_run_at,omitempty"`
	LastSuccessAt string `json:"last_success_at,omitempty"`
	NextRunAt     string `json:"next_run_at,omitempty"`
	LastReason    string `json:"last_reason,omitempty"`
	LastExitCode  int    `json:"last_exit_code"`
	LastError     string `json:"last_error,omitempty"`
	ScanCount     int    `json:"scan_count"`
}

// DaemonRuntimeState synchronizes mutable scan scheduler state across handlers.
type DaemonRuntimeState struct {
	mu             sync.RWMutex
	running        bool
	lastRunAt      time.Time
	lastSuccess    time.Time
	nextRunAt      time.Time
	lastReason     string
	lastError      string
	lastExit       int
	scanCount      int
	lastReport     model.Report
	hasReport      bool
	totalFindings  int64
	lastDurationMs int64
	rulesLoaded    int
	lastScanEpoch  int64
}

// ParseServeFlags parses `skeptic serve` flags and builds a DaemonConfig.
// On -h/--help it returns ErrServeHelpRequested.
func ParseServeFlags(serveArgs []string, stderr io.Writer) (DaemonConfig, error) {
	var (
		bindAddr             string
		scanIntervalRaw      string
		cronRaw              string
		runOnStart           bool
		authTokenRaw         string
		authTokenFile        string
		allowUnauthenticated bool
		dryRun               bool
		watchMode            bool
		watchPaths           string
		verbosity            int
		quiet                bool
		logFilePath          string
		pprofAddr            string
		scanPath             string
		reportFile           string
	)

	fs := flag.NewFlagSet("skeptic serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		config.PrintFormattedFlags(fs, stderr, map[string]string{
			"n": "dry-run",
			"p": "path",
		}, nil)
	}
	fs.StringVar(&bindAddr, "bind", "127.0.0.1:7788", "HTTP listen address")
	fs.StringVar(&scanIntervalRaw, "scan-interval", "5m", "schedule interval (e.g. 30s, 5m, 1h)")
	fs.StringVar(&scanIntervalRaw, "interval", "5m", "alias for --scan-interval")
	fs.StringVar(&cronRaw, "cron", "", "cron interval (@every <duration>)")
	fs.BoolVar(&runOnStart, "run-on-start", true, "run initial scan on startup")
	fs.StringVar(&authTokenRaw, "auth-token", "", "bearer token for API auth")
	fs.StringVar(&authTokenFile, "auth-token-file", "", "file containing bearer token")
	fs.BoolVar(&allowUnauthenticated, "allow-unauthenticated", false, "disable HTTP auth (not recommended)")
	fs.BoolVar(&dryRun, "dry-run", false, "print resolved config and exit")
	fs.BoolVar(&dryRun, "n", false, "print resolved config and exit")
	fs.BoolVar(&watchMode, "watch", false, "enable fs event polling (triggers scan on changes)")
	fs.StringVar(&watchPaths, "watch-paths", ".", "comma-separated watch paths (used with --watch)")
	fs.IntVar(&verbosity, "verbose", 0, "verbosity: 0=warn, 1=info, 2=debug")
	fs.BoolVar(&quiet, "quiet", false, "suppress non-error output")
	fs.StringVar(&logFilePath, "log-file", "", "write logs to file (empty = stderr only)")
	fs.StringVar(&pprofAddr, "pprof", "", "pprof HTTP endpoint (e.g. localhost:6060)")
	fs.StringVar(&scanPath, "path", "", "path to scan (consistent with skeptic scan --path)")
	fs.StringVar(&scanPath, "p", "", "shorthand for --path")
	fs.StringVar(&reportFile, "report-file", "", "write latest scan report JSON to this file (default: skeptic data dir)")

	if err := fs.Parse(serveArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return DaemonConfig{}, ErrServeHelpRequested
		}
		return DaemonConfig{}, fmt.Errorf("%w: %v", errServeFlagParse, err)
	}

	interval, err := ResolveServeInterval(scanIntervalRaw, cronRaw)
	if err != nil {
		return DaemonConfig{}, fmt.Errorf("invalid schedule options: %v", err)
	}
	scanArgs, err := SanitizeServeScanArgs(fs.Args())
	if err != nil {
		return DaemonConfig{}, fmt.Errorf("invalid serve scan args: %v", err)
	}
	// --path/-p is forwarded as a scan arg so it is consistent with skeptic scan --path.
	// Positional args after serve flags still work for backward compatibility.
	if p := strings.TrimSpace(scanPath); p != "" {
		scanArgs = append([]string{"--path", p}, scanArgs...)
	}

	visited := make(map[string]struct{}, 16)
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = struct{}{} })

	return DaemonConfig{
		BindAddr:             bindAddr,
		Interval:             interval,
		RunOnStart:           runOnStart,
		AuthTokenRaw:         authTokenRaw,
		AuthTokenFile:        authTokenFile,
		AllowUnauthenticated: allowUnauthenticated,
		DryRun:               dryRun,
		WatchMode:            watchMode,
		WatchPaths:           watchPaths,
		Verbosity:            verbosity,
		Quiet:                quiet,
		LogFilePath:          logFilePath,
		ReportFile:           reportFile,
		PprofAddr:            pprofAddr,
		ScanArgs:             scanArgs,
		visitedFlags:         visited,
	}, nil
}

// SetupDaemonRoutes registers daemon HTTP handlers on mux.
func SetupDaemonRoutes(
	mux *http.ServeMux,
	authToken string,
	allowUnauthenticated bool,
	state *DaemonRuntimeState,
	triggerCh chan<- string,
	bindAddr string,
	interval time.Duration,
) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"service": "skeptic-daemon",
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		if !ServeAuthOK(r, authToken, allowUnauthenticated) {
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		WriteJSON(w, http.StatusOK, state.Status(bindAddr, interval))
	})
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		if !ServeAuthOK(r, authToken, allowUnauthenticated) {
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		report, ok := state.Report()
		if !ok {
			WriteJSON(w, http.StatusNotFound, map[string]string{"error": "no report available yet"})
			return
		}
		q := r.URL.Query()
		WriteJSON(w, http.StatusOK, filterReportForResponse(report, q.Get("top"), q.Get("min_severity")))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "use GET", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		state.WriteMetrics(w)
	})
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if !ServeAuthOK(r, authToken, allowUnauthenticated) {
			WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if r.Method != http.MethodPost {
			WriteJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		select {
		case triggerCh <- "api":
			WriteJSON(w, http.StatusAccepted, map[string]string{"status": "scan scheduled"})
		default:
			WriteJSON(w, http.StatusAccepted, map[string]string{"status": "scan already pending"})
		}
	})
}

// AwaitShutdownSignal blocks until SIGINT/SIGTERM, parent context cancellation, or a fatal
// server error, then shuts down gracefully.
func AwaitShutdownSignal(
	ctx context.Context,
	server *http.Server,
	pprofServer *http.Server,
	serverErrCh <-chan error,
	cancelScheduler context.CancelFunc,
	schedulerDoneCh <-chan struct{},
	logger *logging.Logger,
) int {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		logger.Infof("daemon received signal %s, shutting down", sig.String())
	case <-ctx.Done():
		logger.Infof("daemon context cancelled, shutting down")
	case serverErr := <-serverErrCh:
		if serverErr != nil {
			logger.Errorf("daemon HTTP server error: %v", serverErr)
			cancelScheduler()
			WaitForSchedulerStop(schedulerDoneCh, logger)
			if pprofServer != nil {
				pctx, pcancel := context.WithTimeout(context.Background(), DefaultDaemonShutdownWait)
				_ = pprofServer.Shutdown(pctx)
				pcancel()
			}
			return 1
		}
	}

	cancelScheduler()
	WaitForSchedulerStop(schedulerDoneCh, logger)
	if pprofServer != nil {
		pctx, pcancel := context.WithTimeout(context.Background(), DefaultDaemonShutdownWait)
		if err := pprofServer.Shutdown(pctx); err != nil {
			logger.Warnf("pprof shutdown warning: %v", err)
		}
		pcancel()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), DefaultDaemonShutdownWait)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Warnf("daemon shutdown warning: %v", err)
	}
	return 0
}

// RunServe starts the local daemon API and background scheduler for periodic scans.
// It parses serve-specific flags from serveArgs (arguments after `skeptic serve`).
// The provided ctx controls the overall daemon lifetime; cancelling it initiates graceful shutdown.
func RunServe(ctx context.Context, serveArgs []string, stdout io.Writer, stderr io.Writer, deps DaemonDeps) int {
	cfg, err := ParseServeFlags(serveArgs, stderr)
	if err != nil {
		if errors.Is(err, ErrServeHelpRequested) {
			return 0
		}
		if errors.Is(err, errServeFlagParse) {
			return 2
		}
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}

	applyGlobalFlagsToDaemonConfig(&cfg, deps.GlobalFlags)
	applySystemConfigToDaemon(&cfg, deps.SystemConfig)

	bindAddr := cfg.BindAddr
	interval := cfg.Interval
	runOnStart := cfg.RunOnStart
	authTokenRaw := cfg.AuthTokenRaw
	authTokenFile := cfg.AuthTokenFile
	allowUnauthenticated := cfg.AllowUnauthenticated
	scanArgs := buildDaemonScanArgs(cfg)

	if cfg.DryRun {
		fmt.Fprintf(stdout, "skeptic serve --dry-run\n")
		fmt.Fprintf(stdout, "  bind:          %s\n", bindAddr)
		fmt.Fprintf(stdout, "  interval:      %s\n", interval)
		fmt.Fprintf(stdout, "  run-on-start:  %t\n", runOnStart)
		fmt.Fprintf(stdout, "  auth:          %s\n", ServeDryRunAuthMode(authTokenRaw, authTokenFile, allowUnauthenticated))
		fmt.Fprintf(stdout, "  pprof:         %s\n", cfg.PprofAddr)
		fmt.Fprintf(stdout, "  scan-args:     %s\n", strings.Join(scanArgs, " "))
		return 0
	}

	authToken := strings.TrimSpace(authTokenRaw)
	if authToken == "" && strings.TrimSpace(authTokenFile) != "" {
		tokenBytes, readErr := os.ReadFile(model.ExpandHomePath(authTokenFile))
		if readErr != nil {
			fmt.Fprintf(stderr, "failed reading auth token file: %v\n", readErr)
			return 2
		}
		authToken = strings.TrimSpace(string(tokenBytes))
	}
	cfg.AuthToken = authToken

	if cfg.LogFilePath != "" {
		if mkErr := os.MkdirAll(filepath.Dir(cfg.LogFilePath), 0o755); mkErr != nil {
			fmt.Fprintf(stderr, "warning: cannot create log directory: %v\n", mkErr)
		}
	}
	if cfg.ReportFile != "" {
		if mkErr := os.MkdirAll(filepath.Dir(cfg.ReportFile), 0o755); mkErr != nil {
			fmt.Fprintf(stderr, "warning: cannot create report directory: %v\n", mkErr)
		}
	}
	logger, logCloser, err := logging.SetupLogger(stderr, cfg.LogFilePath, cfg.Quiet, cfg.Verbosity)
	if err != nil {
		fmt.Fprintf(stderr, "failed to initialize logger: %v\n", err)
		return 1
	}
	if logCloser != nil {
		defer func() {
			if cerr := logCloser.Close(); cerr != nil {
				fmt.Fprintf(stderr, "warning: close log file: %v\n", cerr)
			}
		}()
	}

	if !allowUnauthenticated && authToken == "" {
		generated, genErr := GenerateServeToken()
		if genErr != nil {
			fmt.Fprintf(stderr, "failed to generate auth token: %v\n", genErr)
			return 1
		}
		authToken = generated
		cfg.AuthToken = authToken
		// Persist the generated token so reconnecting clients (e.g. the MCP
		// server) can pick it up from the stable data-dir location.
		if cfg.AuthTokenFile != "" {
			if mkErr := os.MkdirAll(filepath.Dir(cfg.AuthTokenFile), 0o700); mkErr == nil {
				_ = os.WriteFile(cfg.AuthTokenFile, []byte(authToken), 0o600)
			}
		}
		logger.Warnf("no auth token configured; generated token written to %s", cfg.AuthTokenFile)
	} else if allowUnauthenticated {
		logger.Warnf("serve authentication disabled (--allow-unauthenticated)")
	}

	state := &DaemonRuntimeState{rulesLoaded: deps.RulesLoaded}
	triggerCh := make(chan string, MaxDaemonScanTriggerBacklog)
	schedulerCtx, schedulerCancel := context.WithCancel(ctx)
	defer schedulerCancel()
	schedulerDoneCh := make(chan struct{})
	go func() {
		RunDaemonScheduler(schedulerCtx, triggerCh, cfg, logger, state, deps)
		close(schedulerDoneCh)
	}()

	mux := http.NewServeMux()
	SetupDaemonRoutes(mux, authToken, allowUnauthenticated, state, triggerCh, bindAddr, interval)

	server := &http.Server{
		Addr:              bindAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       DaemonHTTPReadTimeout,
		WriteTimeout:      DaemonHTTPWriteTimeout,
		IdleTimeout:       DaemonHTTPIdleTimeout,
	}
	serverErrCh := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	var pprofServer *http.Server
	if strings.TrimSpace(cfg.PprofAddr) != "" {
		pprofServer = &http.Server{
			Addr:    cfg.PprofAddr,
			Handler: http.DefaultServeMux,
		}
		go func() {
			if err := pprofServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Errorf("pprof server error: %v", err)
			}
		}()
		logger.Infof("pprof listening on %s", cfg.PprofAddr)
	}

	if cfg.WatchMode {
		paths := strings.Split(cfg.WatchPaths, ",")
		for i := range paths {
			paths[i] = strings.TrimSpace(paths[i])
		}
		go RunFSWatchPoller(schedulerCtx, triggerCh, paths, 2*time.Second, logger)
		logger.Infof("filesystem watch mode enabled for %d paths", len(paths))
	}

	logger.Infof(
		"skeptic daemon listening on %s (interval=%s run_on_start=%t watch=%t)",
		bindAddr,
		interval,
		runOnStart,
		cfg.WatchMode,
	)

	return AwaitShutdownSignal(ctx, server, pprofServer, serverErrCh, schedulerCancel, schedulerDoneCh, logger)
}

// ResolveServeInterval normalizes scan cadence from explicit duration or @every cron shorthand.
func ResolveServeInterval(scanIntervalRaw string, cronRaw string) (time.Duration, error) {
	cronValue := strings.TrimSpace(cronRaw)
	if cronValue != "" {
		lower := strings.ToLower(cronValue)
		if !strings.HasPrefix(lower, "@every ") {
			return 0, errors.New(`--cron currently supports only "@every <duration>"`)
		}
		durationText := strings.TrimSpace(cronValue[len("@every "):])
		if durationText == "" {
			return 0, errors.New(`missing duration in --cron "@every <duration>"`)
		}
		d, err := time.ParseDuration(durationText)
		if err != nil {
			return 0, err
		}
		if d <= 0 {
			return 0, errors.New("cron interval must be > 0")
		}
		return d, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(scanIntervalRaw))
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, errors.New("scan-interval must be > 0")
	}
	return d, nil
}

// SanitizeServeScanArgs blocks nested subcommands and keeps daemon-triggered scans deterministic.
func SanitizeServeScanArgs(args []string) ([]string, error) {
	if len(args) == 0 {
		return []string{}, nil
	}
	first := strings.ToLower(strings.TrimSpace(args[0]))
	switch first {
	case "serve", "daemon", "ingest", "sign-rulepack", "gen-rule-keypair", "init-config", "init", "config":
		return nil, fmt.Errorf("scan args cannot include subcommand %q", first)
	default:
		return append([]string{}, args...), nil
	}
}

// GenerateServeToken creates an ephemeral high-entropy bearer token for local daemon control.
func GenerateServeToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// ServeAuthOK validates bearer auth using constant-time comparison to reduce token oracle leakage.
func ServeAuthOK(r *http.Request, token string, allowUnauthenticated bool) bool {
	if allowUnauthenticated || strings.TrimSpace(token) == "" {
		return true
	}
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return false
	}
	provided := strings.TrimSpace(header[len("Bearer "):])
	if provided == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
}

// RunDaemonScheduler serializes scan triggers so only one scan runs at a time.
func RunDaemonScheduler(
	ctx context.Context,
	triggerCh <-chan string,
	cfg DaemonConfig,
	logger *logging.Logger,
	state *DaemonRuntimeState,
	deps DaemonDeps,
) {
	execute := func(reason string) {
		if !state.BeginRun(reason) {
			logger.Warnf("daemon scan trigger skipped; scan already running")
			return
		}
		report, exitCode, stderrText, err := deps.ExecuteScan(cfg.ScanArgs, logger, deps.Scan)
		state.EndRun(report, exitCode, err)
		if strings.TrimSpace(stderrText) != "" {
			logger.Warnf("daemon scan stderr: %s", strings.TrimSpace(stderrText))
		}
		if err != nil {
			logger.Warnf("daemon scan error: %v", err)
			return
		}
		logger.Infof(
			"daemon scan complete reason=%s findings=%d scanned=%d exit=%d",
			reason,
			len(report.Findings),
			report.ScannedFiles,
			exitCode,
		)
		if cfg.ReportFile != "" {
			if data, encErr := json.Marshal(report); encErr == nil {
				if writeErr := os.WriteFile(cfg.ReportFile, data, 0o644); writeErr != nil {
					logger.Warnf("daemon: failed to write report file %s: %v", cfg.ReportFile, writeErr)
				} else {
					logger.Debugf("daemon: report written to %s", cfg.ReportFile)
				}
			}
		}
	}

	if cfg.RunOnStart {
		execute("startup")
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	state.SetNextRun(time.Now().Add(cfg.Interval))

	for {
		select {
		case <-ctx.Done():
			return
		case reason := <-triggerCh:
			execute(reason)
		case <-ticker.C:
			state.SetNextRun(time.Now().Add(cfg.Interval))
			execute("schedule")
		}
	}
}

// BeginRun attempts to transition scheduler state to running; returns false if a run is already active.
func (s *DaemonRuntimeState) BeginRun(reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return false
	}
	s.running = true
	s.lastReason = reason
	s.lastRunAt = time.Now().UTC()
	return true
}

// EndRun finalizes scheduler state for both successful and failed scan executions.
func (s *DaemonRuntimeState) EndRun(report model.Report, exitCode int, runErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	s.scanCount++
	s.lastExit = exitCode
	s.lastScanEpoch = time.Now().Unix()
	if runErr != nil {
		s.lastError = runErr.Error()
		return
	}
	s.lastError = ""
	s.lastSuccess = time.Now().UTC()
	s.lastReport = report
	s.hasReport = true
	s.totalFindings += int64(len(report.Findings))
	elapsed := time.Since(s.lastRunAt)
	s.lastDurationMs = elapsed.Milliseconds()
}

// WriteMetrics emits Prometheus text-format metrics for external scraping.
func (s *DaemonRuntimeState) WriteMetrics(w io.Writer) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fmt.Fprintf(w, "# HELP skeptic_scans_total Total number of scans executed.\n")
	fmt.Fprintf(w, "# TYPE skeptic_scans_total counter\n")
	fmt.Fprintf(w, "skeptic_scans_total %d\n", s.scanCount)
	fmt.Fprintf(w, "# HELP skeptic_findings_total Total findings across all scans.\n")
	fmt.Fprintf(w, "# TYPE skeptic_findings_total counter\n")
	fmt.Fprintf(w, "skeptic_findings_total %d\n", s.totalFindings)
	fmt.Fprintf(w, "# HELP skeptic_scan_duration_seconds Duration of last scan in seconds.\n")
	fmt.Fprintf(w, "# TYPE skeptic_scan_duration_seconds gauge\n")
	fmt.Fprintf(w, "skeptic_scan_duration_seconds %.3f\n", float64(s.lastDurationMs)/1000.0)
	fmt.Fprintf(w, "# HELP skeptic_rules_loaded Number of rules loaded.\n")
	fmt.Fprintf(w, "# TYPE skeptic_rules_loaded gauge\n")
	fmt.Fprintf(w, "skeptic_rules_loaded %d\n", s.rulesLoaded)
	fmt.Fprintf(w, "# HELP skeptic_last_scan_epoch Unix timestamp of last scan.\n")
	fmt.Fprintf(w, "# TYPE skeptic_last_scan_epoch gauge\n")
	fmt.Fprintf(w, "skeptic_last_scan_epoch %d\n", s.lastScanEpoch)
	if s.hasReport {
		for sev, count := range s.lastReport.FindingsBySeverity {
			fmt.Fprintf(w, "skeptic_findings_by_severity{severity=%q} %d\n", sev, count)
		}
	}
}

// SetNextRun records scheduler intent for status visibility.
func (s *DaemonRuntimeState) SetNextRun(next time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextRunAt = next.UTC()
}

// Report returns the latest successful report snapshot, if available.
func (s *DaemonRuntimeState) Report() (model.Report, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastReport, s.hasReport
}

// Status constructs an immutable status payload for HTTP clients.
func (s *DaemonRuntimeState) Status(bindAddr string, interval time.Duration) DaemonStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return DaemonStatus{
		ListenAddress: bindAddr,
		Interval:      interval.String(),
		Running:       s.running,
		LastRunAt:     FormatTimestamp(s.lastRunAt),
		LastSuccessAt: FormatTimestamp(s.lastSuccess),
		NextRunAt:     FormatTimestamp(s.nextRunAt),
		LastReason:    s.lastReason,
		LastExitCode:  s.lastExit,
		LastError:     s.lastError,
		ScanCount:     s.scanCount,
	}
}

// FormatTimestamp converts zero/initialized timestamps into API-safe strings.
func FormatTimestamp(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

// filterReportForResponse applies server-side ?top=N and ?min_severity=X filters
// to a report copy before JSON serialization. Large scans can produce tens of
// thousands of findings; without filtering the response easily exceeds client
// read limits and overwhelms LLM context windows. Findings are sorted by
// severity descending before truncation so callers always receive the most
// important results first.
func filterReportForResponse(r model.Report, topRaw, minSevRaw string) model.Report {
	findings := make([]model.Finding, len(r.Findings))
	copy(findings, r.Findings)

	if minSevRaw != "" {
		if minSev, err := model.ParseSeverity(minSevRaw); err == nil {
			minRank := model.SeverityWeight(minSev)
			filtered := findings[:0:0]
			for _, f := range findings {
				if model.SeverityWeight(f.Severity) >= minRank {
					filtered = append(filtered, f)
				}
			}
			findings = filtered
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return model.SeverityWeight(findings[i].Severity) > model.SeverityWeight(findings[j].Severity)
	})

	if topRaw != "" {
		if n, err := strconv.Atoi(topRaw); err == nil && n > 0 && n < len(findings) {
			findings = findings[:n]
		}
	} else if len(findings) > 500 {
		findings = findings[:500]
	}

	r.Findings = findings
	return r
}

// WriteJSON writes canonical API responses with explicit JSON content-type.
// It encodes to a buffer before writing headers so encoding failures produce
// a clean 500 rather than a half-sent response with contradictory status codes.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	data, err := json.Marshal(payload)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal encoding failure"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n"))
}

// WaitForSchedulerStop avoids returning while background scheduler work may still be running.
func WaitForSchedulerStop(doneCh <-chan struct{}, logger *logging.Logger) {
	select {
	case <-doneCh:
		return
	case <-time.After(DaemonSchedulerStopWait):
		logger.Warnf("daemon scheduler did not stop within %s", DaemonSchedulerStopWait)
		return
	}
}

// RunFSWatchPoller polls filesystem paths for mtime changes and triggers scans with debounce.
func RunFSWatchPoller(ctx context.Context, triggerCh chan<- string, paths []string, debounce time.Duration, logger *logging.Logger) {
	snapshots := make(map[string]time.Time)
	for _, p := range paths {
		info, err := os.Stat(p)
		if err == nil {
			snapshots[p] = info.ModTime()
		}
	}
	ticker := time.NewTicker(debounce)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed := false
			for _, p := range paths {
				info, err := os.Stat(p)
				if err != nil {
					continue
				}
				prev, ok := snapshots[p]
				if !ok || info.ModTime().After(prev) {
					snapshots[p] = info.ModTime()
					changed = true
				}
			}
			if changed {
				select {
				case triggerCh <- "fswatch":
					logger.Debugf("filesystem change detected, scan triggered")
				default:
				}
			}
		}
	}
}

// ServeDryRunAuthMode summarizes the authentication mode for dry-run output.
func ServeDryRunAuthMode(tokenRaw, tokenFile string, allowUnauth bool) string {
	if allowUnauth {
		return "unauthenticated (open)"
	}
	if strings.TrimSpace(tokenRaw) != "" {
		return "bearer token (inline)"
	}
	if strings.TrimSpace(tokenFile) != "" {
		return "bearer token (file)"
	}
	return "ephemeral (auto-generated)"
}

// applyGlobalFlagsToDaemonConfig merges CLI global flags into the daemon config
// when the user didn't explicitly set the corresponding serve flag.
func applyGlobalFlagsToDaemonConfig(cfg *DaemonConfig, gf GlobalFlagOverrides) {
	_, verbSet := cfg.visitedFlags["verbose"]
	if !verbSet && gf.Verbosity > cfg.Verbosity {
		cfg.Verbosity = gf.Verbosity
	}
	_, quietSet := cfg.visitedFlags["quiet"]
	if !quietSet && gf.Quiet {
		cfg.Quiet = true
	}
	if cfg.ConfigPath == "" && gf.Config != "" {
		cfg.ConfigPath = gf.Config
	}
	_, logSet := cfg.visitedFlags["log-file"]
	if !logSet && cfg.LogFilePath == "" && gf.LogFile != "" {
		cfg.LogFilePath = gf.LogFile
	}
}

// applySystemConfigToDaemon applies daemon-specific system config settings when
// the user didn't override them via flags. All file paths default to the
// skeptic data directory so that tokens, logs, and reports land in one place.
func applySystemConfigToDaemon(cfg *DaemonConfig, sys SystemDaemonConfig) {
	_, bindSet := cfg.visitedFlags["bind"]
	if !bindSet && sys.DaemonBind != "" {
		cfg.BindAddr = sys.DaemonBind
	}

	// Default token file to the data dir. Always set the path so the daemon
	// writes a fresh token there on startup rather than generating one in memory
	// or leaving it in a temp dir.
	_, tokenFileSet := cfg.visitedFlags["auth-token-file"]
	if !tokenFileSet && cfg.AuthTokenFile == "" && cfg.AuthTokenRaw == "" && sys.DaemonTokenDir != "" {
		cfg.AuthTokenFile = filepath.Join(sys.DaemonTokenDir, "daemon.token")
	}

	// Default log file to the data dir logs/ subdirectory.
	_, logSet := cfg.visitedFlags["log-file"]
	if !logSet && cfg.LogFilePath == "" && sys.LogDir != "" {
		cfg.LogFilePath = filepath.Join(sys.LogDir, "daemon.log")
	}

	// Default report file to the data dir root.
	_, reportSet := cfg.visitedFlags["report-file"]
	if !reportSet && cfg.ReportFile == "" && sys.LogDir != "" {
		cfg.ReportFile = filepath.Join(filepath.Dir(sys.LogDir), "daemon-report.json")
	}
}

// buildDaemonScanArgs prepends daemon-level config/verbosity/quiet flags to the
// user-provided scan args so that scheduled scans inherit the daemon's settings.
func buildDaemonScanArgs(cfg DaemonConfig) []string {
	var extra []string
	if cfg.ConfigPath != "" {
		extra = append(extra, "--config", cfg.ConfigPath)
	}
	if cfg.Verbosity > 0 {
		extra = append(extra, "--verbose", fmt.Sprintf("%d", cfg.Verbosity))
	}
	if cfg.Quiet {
		extra = append(extra, "--quiet")
	}
	if len(extra) == 0 {
		return cfg.ScanArgs
	}
	return append(extra, cfg.ScanArgs...)
}

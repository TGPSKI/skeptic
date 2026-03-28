package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/config"
	"github.com/TGPSKI/skeptic/internal/daemon"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

// MCP JSON-RPC protocol and scan-resource defaults.
const (
	DefaultMCPProtocolVersion = "2025-03-26"
	MaxMCPMessageBytes        = 8 * 1024 * 1024
	DefaultMCPScanMaxFiles    = 200000
	DefaultMCPScanMaxFindings = 500
	DefaultMCPSampleLimit     = 25
)

// MCPRequest represents a JSON-RPC request frame sent by an MCP client.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// MCPResponse represents a JSON-RPC response frame emitted by this MCP server.
type MCPResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *MCPError `json:"error,omitempty"`
}

// MCPError provides structured JSON-RPC error details for tool callers.
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPToolsCallParams models the payload of tools/call requests.
type MCPToolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// PendingIngestRequest stores a deferred URL ingestion awaiting human approval.
type PendingIngestRequest struct {
	URL     string
	OutFile string
	Args    map[string]any
}

// MCPAuditEntry records tool invocations for security audit trails.
type MCPAuditEntry struct {
	Timestamp  string `json:"timestamp"`
	Tool       string `json:"tool"`
	Status     string `json:"status"`
	DurationMs int64  `json:"duration_ms"`
	Args       string `json:"args,omitempty"`
}

// RunScanFunc runs a skeptic scan CLI invocation (typically package main's run).
type RunScanFunc func(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int

// RunIngestFunc runs the ingest subcommand (typically package main's runIngest).
type RunIngestFunc func(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) int

// DefaultRulesFunc returns built-in rules for MCP resources.
type DefaultRulesFunc func() []model.Rule

// MCPServerState stores server configuration and mutable runtime state for the MCP session.
type MCPServerState struct {
	DaemonClient          *daemon.DaemonAPIClient
	AllowTrigger          bool
	AllowIngest           bool
	RequireIngestApproval bool
	TriggerCooldown       time.Duration
	LastTriggerAt         time.Time
	PendingIngest         *PendingIngestRequest
	AllowedScanRoots      []string
	IngestAllowedHosts    []string
	RulesOutDir           string
	// ReportFile is the path to the durable daemon-report.json written after each scan.
	// Used by the skeptic://report/latest resource so it survives daemon restarts.
	ReportFile   string
	Logger       *logging.Logger
	AuditLog     []MCPAuditEntry
	AuditLogPath string
	RunScan      RunScanFunc
	RunIngest    RunIngestFunc
	DefaultRules DefaultRulesFunc
}

// Options configures RunMCP callbacks and rule loading.
type Options struct {
	RunScan      RunScanFunc
	RunIngest    RunIngestFunc
	DefaultRules DefaultRulesFunc
}

// RunMCP starts a local stdio MCP server for safe, agentic skeptic operations.
func RunMCP(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, opts Options) int {
	if opts.RunScan == nil || opts.RunIngest == nil || opts.DefaultRules == nil {
		fmt.Fprintln(stderr, "mcp: RunMCP requires RunScan, RunIngest, and DefaultRules callbacks")
		return 2
	}
	var (
		daemonURL       string
		daemonToken     string
		daemonTokenFile string
		rulesOutDir     string
		allowRemote     bool
		allowTrigger    bool
		allowIngest     bool
		verbosity       int
		quiet           bool
		logFilePath     string
	)

	var (
		requireIngestApproval bool
		triggerCooldownRaw    string
		auditLogPath          string
		allowedScanRootsRaw   string
		mcpIngestAllowedHosts string
	)

	fs := flag.NewFlagSet("skeptic mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		config.PrintFormattedFlags(fs, stderr, nil, nil)
	}
	fs.StringVar(&daemonURL, "daemon-url", "http://127.0.0.1:7788", "skeptic daemon URL")
	fs.StringVar(&daemonToken, "daemon-token", "", "daemon bearer token")
	fs.StringVar(&daemonTokenFile, "daemon-token-file", "", "file containing daemon bearer token")
	fs.StringVar(&rulesOutDir, "rules-out-dir", "rulepacks/campaigns", "directory for generated rule packs")
	fs.BoolVar(&allowRemote, "allow-remote-daemon", false, "allow non-loopback daemon URLs (not recommended)")
	fs.BoolVar(&allowTrigger, "allow-trigger", true, "enable daemon trigger tool")
	fs.BoolVar(&allowIngest, "allow-ingest", true, "enable threat-intel ingestion tool")
	fs.BoolVar(&requireIngestApproval, "require-ingest-approval", false, "require approval before ingestion executes")
	fs.StringVar(&allowedScanRootsRaw, "mcp-allowed-roots", "", "restrict scan_repo to these directory prefixes (comma-sep; default: unrestricted — any valid git repository is accepted)")
	fs.StringVar(&mcpIngestAllowedHosts, "mcp-ingest-allowed-hosts", "", "allowed hosts for ingest_url (comma-sep; required for ingest)")
	fs.StringVar(&triggerCooldownRaw, "mcp-trigger-cooldown", "30s", "min interval between scan triggers (Go duration, e.g. 30s)")
	fs.StringVar(&auditLogPath, "audit-log", "", "MCP audit log path (JSON lines)")
	var autoDaemon bool
	var autoDaemonArgs string
	fs.BoolVar(&autoDaemon, "auto-daemon", false, "auto-start local daemon; stop on MCP exit")
	fs.StringVar(&autoDaemonArgs, "auto-daemon-args", "", "extra args for auto-started daemon")
	fs.IntVar(&verbosity, "verbose", 0, "verbosity: 0=warn, 1=info, 2=debug")
	fs.BoolVar(&quiet, "quiet", false, "suppress non-error output")
	fs.StringVar(&logFilePath, "log-file", "", "write logs to file (empty = stderr only)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if len(fs.Args()) > 0 {
		fmt.Fprintln(stderr, "mcp mode does not accept positional arguments")
		return 2
	}
	triggerCooldown, err := time.ParseDuration(strings.TrimSpace(triggerCooldownRaw))
	if err != nil || triggerCooldown < 0 {
		fmt.Fprintf(stderr, "invalid --mcp-trigger-cooldown: %s\n", triggerCooldownRaw)
		return 2
	}

	allowedScanRoots, err := ResolveMCPAllowedScanRoots(allowedScanRootsRaw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid --mcp-allowed-roots: %v\n", err)
		return 2
	}
	ingestAllowedHosts := ParseMCPIngestAllowedHosts(mcpIngestAllowedHosts)

	// When --auto-daemon is set, defer token-file read until after the daemon
	// starts — the file may not exist yet (auto-daemon creates it on startup).
	if !autoDaemon && strings.TrimSpace(daemonToken) == "" && strings.TrimSpace(daemonTokenFile) != "" {
		tokenBytes, err := os.ReadFile(model.ExpandHomePath(daemonTokenFile))
		if err != nil {
			fmt.Fprintf(stderr, "failed reading daemon token file: %v\n", err)
			return 2
		}
		daemonToken = strings.TrimSpace(string(tokenBytes))
	}

	logger, logCloser, err := logging.SetupLogger(stderr, logFilePath, quiet, verbosity)
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

	if autoDaemon {
		proc, token, stopFn, err := startAutoDaemon(ctx, daemonURL, autoDaemonArgs, logger, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "auto-daemon: failed to start: %v\n", err)
			return 1
		}
		defer stopFn()
		if daemonToken == "" {
			daemonToken = token
		}
		logger.Infof("auto-daemon: started pid=%d", proc.Pid)

		// Now that auto-daemon is running, read the token file if still needed.
		if daemonToken == "" && strings.TrimSpace(daemonTokenFile) != "" {
			tokenBytes, readErr := os.ReadFile(model.ExpandHomePath(daemonTokenFile))
			if readErr != nil {
				fmt.Fprintf(stderr, "failed reading daemon token file after auto-daemon start: %v\n", readErr)
				return 2
			}
			daemonToken = strings.TrimSpace(string(tokenBytes))
		}
	}

	client, err := daemon.NewDaemonAPIClient(daemonURL, daemonToken, allowRemote)
	if err != nil {
		fmt.Fprintf(stderr, "invalid daemon configuration: %v\n", err)
		return 2
	}
	absRulesOutDir, err := filepath.Abs(model.ExpandHomePath(rulesOutDir))
	if err != nil {
		fmt.Fprintf(stderr, "invalid --rules-out-dir: %v\n", err)
		return 2
	}
	if err := os.MkdirAll(absRulesOutDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "failed to create rules output directory: %v\n", err)
		return 1
	}

	state := &MCPServerState{
		DaemonClient:          client,
		AllowTrigger:          allowTrigger,
		AllowIngest:           allowIngest,
		RequireIngestApproval: requireIngestApproval,
		TriggerCooldown:       triggerCooldown,
		AllowedScanRoots:      allowedScanRoots,
		IngestAllowedHosts:    ingestAllowedHosts,
		RulesOutDir:           absRulesOutDir,
		ReportFile:            config.DaemonReportPath(),
		Logger:                logger,
		AuditLogPath:          strings.TrimSpace(auditLogPath),
		RunScan:               opts.RunScan,
		RunIngest:             opts.RunIngest,
		DefaultRules:          opts.DefaultRules,
	}

	logger.Infof(
		"starting local MCP server daemon_url=%s allow_trigger=%t allow_ingest=%t",
		client.BaseURL,
		allowTrigger,
		allowIngest,
	)
	return RunMCPServerLoop(ctx, os.Stdin, stdout, state)
}

// ResolveMCPAllowedScanRoots expands and validates scan root prefixes.
// When raw is empty no restriction is applied; any valid git repository path is accepted.
// Explicit roots are resolved to absolute paths and symlinks are followed.
func ResolveMCPAllowedScanRoots(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var parts []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		parts = append(parts, p)
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		abs, err := filepath.Abs(model.ExpandHomePath(p))
		if err != nil {
			return nil, err
		}
		if sym, err := filepath.EvalSymlinks(abs); err == nil {
			abs = sym
		}
		out = append(out, filepath.Clean(abs))
	}
	return out, nil
}

// ParseMCPIngestAllowedHosts parses a comma-separated host allowlist.
func ParseMCPIngestAllowedHosts(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var hosts []string
	for _, h := range strings.Split(raw, ",") {
		h = strings.TrimSpace(strings.ToLower(h))
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// CheckMCPIngestHostAllowed verifies the URL host against the allowlist.
func CheckMCPIngestHostAllowed(sourceURL string, allowed []string) error {
	if len(allowed) == 0 {
		return errors.New("ingest via MCP requires --mcp-ingest-allowed-hosts")
	}
	parsed, err := url.Parse(strings.TrimSpace(sourceURL))
	if err != nil {
		return fmt.Errorf("invalid source_url: %w", err)
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" {
		return errors.New("source_url has no host")
	}
	for _, h := range allowed {
		if host == h {
			return nil
		}
	}
	return fmt.Errorf("host %q is not allowed by --mcp-ingest-allowed-hosts", host)
}

// PathUnderAllowedScanRoots returns true if resolved is under one of the allowed roots.
// An empty allowed list means no restriction: any path is permitted.
func PathUnderAllowedScanRoots(resolved string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	resolved = filepath.Clean(resolved)
	for _, root := range allowed {
		r := filepath.Clean(root)
		if resolved == r {
			return true
		}
		if strings.HasPrefix(resolved, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// RunMCPServerLoop handles framed JSON-RPC messages over stdio.
func RunMCPServerLoop(ctx context.Context, input io.Reader, output io.Writer, state *MCPServerState) int {
	reader := bufio.NewReader(input)
	writer := bufio.NewWriter(output)
	for {
		if ctx.Err() != nil {
			if flushErr := writer.Flush(); flushErr != nil {
				state.Logger.Warnf("mcp flush on context cancel: %v", flushErr)
			}
			return 0
		}
		payload, err := ReadMCPFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if flushErr := writer.Flush(); flushErr != nil {
					state.Logger.Warnf("mcp flush on EOF: %v", flushErr)
				}
				return 0
			}
			state.Logger.Warnf("mcp read frame error: %v", err)
			return 1
		}

		var req MCPRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			state.Logger.Warnf("invalid mcp request payload: %v", err)
			var rawMsg map[string]any
			if json.Unmarshal(payload, &rawMsg) == nil {
				if id, ok := rawMsg["id"]; ok && id != nil {
					errResp := MCPResponse{
						JSONRPC: "2.0",
						ID:      id,
						Error:   &MCPError{Code: -32600, Message: "Invalid Request: " + err.Error()},
					}
					if wErr := WriteMCPFrame(writer, errResp); wErr != nil {
						state.Logger.Warnf("mcp write error response: %v", wErr)
						return 1
					}
				}
			}
			continue
		}
		resp, shouldRespond := HandleMCPRequest(req, state)
		if !shouldRespond {
			continue
		}
		if err := WriteMCPFrame(writer, resp); err != nil {
			state.Logger.Warnf("mcp write frame error: %v", err)
			return 1
		}
	}
}

// HandleMCPRequest routes MCP methods and builds deterministic responses.
func HandleMCPRequest(req MCPRequest, state *MCPServerState) (MCPResponse, bool) {
	response := MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}
	respond := req.ID != nil

	switch req.Method {
	case "initialize":
		response.Result = map[string]any{
			"protocolVersion": DefaultMCPProtocolVersion,
			"capabilities": map[string]any{
				"tools":     map[string]any{},
				"resources": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "skeptic-mcp",
				"version": "0.2.0",
			},
			"instructions": "Local-only skeptic MCP bridge. Exposes scan, daemon, ingest, and waiver tools plus rule/report resources. Use tools/list, tools/call, resources/list, and resources/read.",
		}
	case "notifications/initialized":
		return MCPResponse{}, false
	case "ping":
		response.Result = map[string]any{}
	case "tools/list":
		response.Result = map[string]any{
			"tools": MCPToolDescriptors(state.AllowTrigger, state.AllowIngest, state.RequireIngestApproval),
		}
	case "resources/list":
		response.Result = HandleMCPResourcesList()
	case "resources/read":
		result, err := HandleMCPResourcesRead(req.Params, state)
		if err != nil {
			response.Error = &MCPError{Code: -32001, Message: err.Error()}
		} else {
			response.Result = result
		}
	case "tools/call":
		start := time.Now()
		var toolName string
		var callParams MCPToolsCallParams
		if json.Unmarshal(req.Params, &callParams) == nil {
			toolName = callParams.Name
		}
		state.recordAudit(toolName, "invoked", 0, redactMCPAuditArgs(req.Params))
		result, err := HandleMCPToolsCall(req.Params, state)
		if err != nil {
			state.recordAudit(toolName, "error", time.Since(start).Milliseconds(), "")
		} else {
			state.recordAudit(toolName, "ok", time.Since(start).Milliseconds(), "")
		}
		if err != nil {
			response.Error = &MCPError{
				Code:    -32001,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}
	default:
		response.Error = &MCPError{
			Code:    -32601,
			Message: fmt.Sprintf("method not found: %s", req.Method),
		}
	}
	return response, respond
}

// ReadMCPFrame reads one newline-delimited JSON-RPC message from stdin.
// Per MCP spec: messages are delimited by newlines and MUST NOT contain embedded newlines.
func ReadMCPFrame(reader *bufio.Reader) ([]byte, error) {
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		if len(trimmed) > MaxMCPMessageBytes {
			return nil, fmt.Errorf("mcp message too large: %d bytes", len(trimmed))
		}
		return trimmed, nil
	}
}

// WriteMCPFrame emits one newline-delimited JSON-RPC message to stdout.
func WriteMCPFrame(writer *bufio.Writer, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(data) > MaxMCPMessageBytes {
		return fmt.Errorf("mcp response too large: %d bytes", len(data))
	}
	data = append(data, '\n')
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Flush()
}

func (s *MCPServerState) recordAudit(tool string, status string, durationMs int64, args string) {
	entry := MCPAuditEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		Tool:       tool,
		Status:     status,
		DurationMs: durationMs,
	}
	if strings.TrimSpace(args) != "" {
		entry.Args = args
	}
	s.AuditLog = append(s.AuditLog, entry)
	if len(s.AuditLog) > 1000 {
		s.AuditLog = s.AuditLog[len(s.AuditLog)-500:]
	}
	if s.AuditLogPath != "" {
		line, err := json.Marshal(entry)
		if err != nil {
			if s.Logger != nil {
				s.Logger.Warnf("audit: json marshal failed: %v", err)
			}
			return
		}
		f, err := os.OpenFile(s.AuditLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			if s.Logger != nil {
				s.Logger.Warnf("audit: open log file: %v", err)
			}
			return
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			if s.Logger != nil {
				s.Logger.Warnf("audit: write log: %v", err)
			}
		}
		if err := f.Close(); err != nil {
			if s.Logger != nil {
				s.Logger.Warnf("audit: close log: %v", err)
			}
		}
	}
}

func anyToString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		if value == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}
}

func anyToBool(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		parsed, err := config.ParseFlexibleBool(typed)
		return err == nil && parsed
	default:
		return false
	}
}

// AnyToInt parses integer-style MCP arguments with a caller-provided default.
func AnyToInt(value any, fallback int) (int, error) {
	if value == nil {
		return fallback, nil
	}
	switch typed := value.(type) {
	case float64:
		return int(typed), nil
	case int:
		return typed, nil
	case int32:
		return int(typed), nil
	case int64:
		return int(typed), nil
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, err
		}
		return int(parsed), nil
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return fallback, nil
		}
		parsed, err := strconv.Atoi(trimmed)
		if err != nil {
			return 0, err
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("unsupported value type %T", value)
	}
}

func redactSensitiveJSONValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return redactSensitiveMap(t)
	case []any:
		out := make([]any, len(t))
		for i, el := range t {
			out[i] = redactSensitiveJSONValue(el)
		}
		return out
	default:
		return v
	}
}

func redactSensitiveMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") ||
			strings.Contains(lk, "key") || strings.Contains(lk, "password") {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = redactSensitiveJSONValue(v)
	}
	return out
}

func redactMCPAuditArgs(paramsRaw json.RawMessage) string {
	var p MCPToolsCallParams
	if err := json.Unmarshal(paramsRaw, &p); err != nil {
		return ""
	}
	wrap := map[string]any{
		"name":      p.Name,
		"arguments": redactSensitiveMap(p.Arguments),
	}
	b, err := json.Marshal(wrap)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

func defaultString(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

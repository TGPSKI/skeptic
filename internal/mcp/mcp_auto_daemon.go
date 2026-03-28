package mcp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/config"
	"github.com/TGPSKI/skeptic/internal/daemon"
	"github.com/TGPSKI/skeptic/internal/logging"
)

// startAutoDaemon launches a skeptic daemon as a child process and waits for
// it to become healthy. It returns the process handle, the auto-generated
// bearer token, and a cleanup function that kills the child.
func startAutoDaemon(ctx context.Context, daemonURL, extraArgs string, logger *logging.Logger, stderr io.Writer) (*os.Process, string, func(), error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, "", nil, fmt.Errorf("cannot locate skeptic binary: %w", err)
	}

	// Pre-generate the token and write it to the stable data-dir location.
	// Using a fixed path (instead of a temp dir) means the MCP server can
	// reconnect to a running daemon across restarts without losing the token,
	// and all daemon artifacts end up in the same well-known directory.
	dataDir := config.SkepticDataDir()
	logsDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logsDir, 0o755); err != nil {
		return nil, "", nil, fmt.Errorf("cannot create skeptic logs directory: %w", err)
	}

	token, err := daemon.GenerateServeToken()
	if err != nil {
		return nil, "", nil, fmt.Errorf("cannot generate daemon token: %w", err)
	}
	tokenFile := config.DaemonTokenPath()
	if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
		return nil, "", nil, fmt.Errorf("cannot write daemon token file %s: %w", tokenFile, err)
	}

	parsed, err := url.Parse(daemonURL)
	if err != nil {
		return nil, "", nil, fmt.Errorf("invalid daemon URL: %w", err)
	}
	bindAddr := parsed.Host
	if bindAddr == "" {
		bindAddr = "127.0.0.1:7788"
	}

	// Default to no startup scan so the daemon never vacuums an unknown CWD on launch.
	// Without --path the daemon scans "." which resolves to the CWD inherited from
	// Cursor/the IDE — often the user's home directory. --run-on-start=false is placed
	// before extraArgs so users can still opt in with "--run-on-start=true" in
	// --auto-daemon-args (last flag wins in Go's flag parser).
	//
	// Base args for the daemon child. --log-file and --report-file point into the
	// skeptic data directory so all daemon artifacts land in one place.
	// --run-on-start=false prevents scanning an unknown CWD on launch; callers
	// can override it with --run-on-start=true in --auto-daemon-args.
	//
	// Supported --auto-daemon-args flags (consistent with skeptic scan):
	//   --path <dir>         directory to scan (same flag name as in skeptic scan)
	//   -p <dir>             shorthand for --path
	//   --scan-interval <d>  schedule interval, e.g. 1h, 30m, 5m
	//   --interval <d>       alias for --scan-interval
	//   --run-on-start       run an initial scan immediately on startup
	//   --watch              enable filesystem-change triggered scans
	args := []string{
		"serve",
		"--bind", bindAddr,
		"--auth-token-file", tokenFile,
		"--log-file", config.DaemonLogPath(),
		"--report-file", config.DaemonReportPath(),
		"--run-on-start=false",
	}
	if extraArgs != "" {
		args = append(args, splitShellArgs(extraArgs)...)
	}

	// Redirect the daemon child's stderr to a file in the data dir so it is
	// captured for diagnostics rather than interleaved with the MCP server output.
	stderrPath := config.DaemonStderrPath()
	stderrFile, stderrErr := os.OpenFile(stderrPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if stderrErr != nil {
		fmt.Fprintf(stderr, "auto-daemon: cannot open stderr log %s: %v (using parent stderr)\n", stderrPath, stderrErr)
		stderrFile = os.Stderr
	}

	cmd := &os.ProcAttr{
		Files: []*os.File{nil, nil, stderrFile},
		Dir:   "",
	}

	proc, err := os.StartProcess(exe, append([]string{exe}, args...), cmd)
	if stderrFile != os.Stderr {
		stderrFile.Close() //nolint:errcheck // parent copy no longer needed after fork
	}
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to start daemon process: %w", err)
	}

	stopFn := func() {
		_ = proc.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_, _ = proc.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = proc.Kill()
			_, _ = proc.Wait()
		}
		logger.Infof("auto-daemon: stopped pid=%d", proc.Pid)
	}

	// Poll for daemon health. Token is already known — no need to re-read the file.
	// On success, the token persists at config.DaemonTokenPath() for reconnects.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			stopFn()
			return nil, "", nil, ctx.Err()
		}
		time.Sleep(250 * time.Millisecond)
		healthURL := daemonURL + "/health"
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		if cerr := resp.Body.Close(); cerr != nil {
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return proc, token, stopFn, nil
		}
	}

	stopFn()
	return nil, "", nil, fmt.Errorf("daemon did not become healthy within 10s")
}

// splitShellArgs splits a string on whitespace while respecting double-quoted
// segments. This handles the common case of paths with spaces in
// --auto-daemon-args (e.g. --path "/home/user/my project").
func splitShellArgs(s string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case !inQuote && (r == ' ' || r == '\t'):
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

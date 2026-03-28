package logging

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveLogLevel(t *testing.T) {
	cases := []struct {
		quiet    bool
		verbose  int
		expected LogLevel
	}{
		{quiet: true, verbose: 2, expected: LogError},
		{quiet: false, verbose: 0, expected: LogWarn},
		{quiet: false, verbose: 1, expected: LogInfo},
		{quiet: false, verbose: 2, expected: LogDebug},
	}
	for _, tc := range cases {
		got := ResolveLogLevel(tc.quiet, tc.verbose)
		if got != tc.expected {
			t.Fatalf("ResolveLogLevel(%v,%d)=%v want=%v", tc.quiet, tc.verbose, got, tc.expected)
		}
	}
}

func TestLoggerWritesAtConfiguredLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(LogInfo, &buf)
	logger.Debugf("debug")
	logger.Infof("info")
	logger.Warnf("warn")
	logger.Errorf("err")

	out := buf.String()
	if strings.Contains(out, "debug") {
		t.Fatalf("debug log should not be emitted at info level")
	}
	for _, phrase := range []string{"info", "warn", "err"} {
		if !strings.Contains(out, phrase) {
			t.Fatalf("expected output to contain %q: %q", phrase, out)
		}
	}
}

func TestSetupLoggerWithFile(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "logs", "skeptic.log")
	var stderr bytes.Buffer

	logger, closer, err := SetupLogger(&stderr, logPath, false, 1)
	if err != nil {
		t.Fatalf("SetupLogger failed: %v", err)
	}
	if closer == nil {
		t.Fatalf("expected file closer for log-file configuration")
	}
	logger.Infof("hello from logger")
	_ = closer.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file failed: %v", err)
	}
	if !strings.Contains(string(data), "hello from logger") {
		t.Fatalf("expected log line in file: %q", string(data))
	}
	if !strings.Contains(stderr.String(), "hello from logger") {
		t.Fatalf("expected mirrored log line on stderr buffer")
	}
}

func TestFilepathAbsExpanded(t *testing.T) {
	abs, err := FilepathAbsExpanded(".")
	if err != nil {
		t.Fatalf("FilepathAbsExpanded failed: %v", err)
	}
	if !filepath.IsAbs(abs) {
		t.Fatalf("expected absolute path, got %q", abs)
	}
}

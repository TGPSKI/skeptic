// Package logging provides a thread-safe, structured logger for skeptic.
package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
)

// LogLevel controls how verbose logging is: messages whose level value is
// greater than the configured level are discarded (Error is lowest, Debug highest).
type LogLevel int

const (
	// LogError is the level for error messages (most severe; lowest numeric value).
	LogError LogLevel = iota
	// LogWarn is the level for warning messages.
	LogWarn
	// LogInfo is the level for informational messages.
	LogInfo
	// LogDebug is the level for verbose diagnostic messages (least severe; highest numeric value).
	LogDebug
)

// Logger writes timestamped, leveled log lines to an io.Writer with mutex serialization.
type Logger struct {
	level LogLevel
	out   io.Writer
	mu    sync.Mutex
}

// NewLogger returns a Logger that writes at or below level to out, or to io.Discard if out is nil.
func NewLogger(level LogLevel, out io.Writer) *Logger {
	if out == nil {
		out = io.Discard
	}
	return &Logger{
		level: level,
		out:   out,
	}
}

// ResolveLogLevel maps CLI quiet and verbosity flags to a LogLevel.
func ResolveLogLevel(quiet bool, verbosity int) LogLevel {
	if quiet {
		return LogError
	}
	switch {
	case verbosity >= 2:
		return LogDebug
	case verbosity == 1:
		return LogInfo
	default:
		return LogWarn
	}
}

// SetupLogger builds a Logger at the level implied by quiet and verbosity.
// If logFilePath is empty, output goes only to stderr; otherwise it also appends to that file
// (creating parent directories as needed) and returns a closer for the file.
func SetupLogger(stderr io.Writer, logFilePath string, quiet bool, verbosity int) (*Logger, io.Closer, error) {
	level := ResolveLogLevel(quiet, verbosity)
	if strings.TrimSpace(logFilePath) == "" {
		return NewLogger(level, stderr), nil, nil
	}

	absPath, err := FilepathAbsExpanded(logFilePath)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, nil, err
	}

	file, err := os.OpenFile(absPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	multi := io.MultiWriter(stderr, file)
	return NewLogger(level, multi), file, nil
}

// Errorf logs a message at LogError level.
func (l *Logger) Errorf(format string, args ...any) {
	l.logf(LogError, format, args...)
}

// Warnf logs a message at LogWarn if the logger's level allows it.
func (l *Logger) Warnf(format string, args ...any) {
	l.logf(LogWarn, format, args...)
}

// Infof logs a message at LogInfo if the logger's level allows it.
func (l *Logger) Infof(format string, args ...any) {
	l.logf(LogInfo, format, args...)
}

// Debugf logs a message at LogDebug if the logger's level allows it.
func (l *Logger) Debugf(format string, args ...any) {
	l.logf(LogDebug, format, args...)
}

func (l *Logger) logf(level LogLevel, format string, args ...any) {
	if l == nil || level > l.level {
		return
	}
	levelText := [...]string{"ERROR", "WARN", "INFO", "DEBUG"}[level]
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("%s [%s] %s\n", time.Now().UTC().Format(time.RFC3339), levelText, msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = io.WriteString(l.out, line)
}

// FilepathAbsExpanded returns the absolute form of path after expanding a leading ~ via model.ExpandHomePath.
func FilepathAbsExpanded(path string) (string, error) {
	return filepath.Abs(model.ExpandHomePath(path))
}

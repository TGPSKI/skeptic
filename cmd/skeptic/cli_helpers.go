package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	reportpkg "github.com/TGPSKI/skeptic/internal/report"
)

func parseOutputFormat(raw string) (model.OutputFormat, error) {
	format := model.OutputFormat(strings.ToLower(strings.TrimSpace(raw)))
	if format == "" {
		format = model.FormatText
	}
	switch format {
	case model.FormatText, model.FormatJSON, model.FormatSARIF, model.FormatMarkdown:
		return format, nil
	default:
		return "", fmt.Errorf("expected one of text|json|sarif|markdown, got %q", raw)
	}
}

func emitReport(stdout io.Writer, stderr io.Writer, report model.Report, outputFormat model.OutputFormat) (model.Report, int) {
	switch outputFormat {
	case model.FormatJSON:
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "json encode failed: %v\n", err)
			return model.Report{}, 1
		}
	case model.FormatSARIF:
		if err := reportpkg.WriteSARIFReport(stdout, report); err != nil {
			fmt.Fprintf(stderr, "sarif encode failed: %v\n", err)
			return model.Report{}, 1
		}
	case model.FormatMarkdown:
		reportpkg.WriteMarkdown(stdout, report)
	default:
		reportpkg.WriteTextReport(stdout, report)
	}
	return report, 0
}

func skepticToolVersion() string {
	c := strings.TrimSpace(buildCommit)
	d := strings.TrimSpace(buildDate)
	if c == "" {
		c = "(unknown)"
	}
	if d == "" {
		return c
	}
	return c + "@" + d
}

// mergeGlobalFlagsIntoArgs re-injects extracted global flags as CLI args so
// that subcommands which parse their own FlagSet see them. When
// includeProfileFlags is true, profiling flags (cpu-profile, mem-profile,
// trace, perf-debug) are included; pass false for subcommands that handle
// profiling via globalProfileAndStop instead.
func mergeGlobalFlagsIntoArgs(gf globalFlags, args []string, includeProfileFlags bool) []string {
	var extra []string
	if gf.Verbosity > 0 {
		extra = append(extra, "--verbose", fmt.Sprintf("%d", gf.Verbosity))
	}
	if gf.Quiet {
		extra = append(extra, "--quiet")
	}
	if includeProfileFlags {
		if gf.CPUProfile != "" {
			extra = append(extra, "--cpu-profile", gf.CPUProfile)
		}
		if gf.MemProfile != "" {
			extra = append(extra, "--mem-profile", gf.MemProfile)
		}
		if gf.Trace != "" {
			extra = append(extra, "--trace", gf.Trace)
		}
		if gf.PerfDebug {
			extra = append(extra, "--perf-debug")
		}
	}
	if gf.LogFile != "" {
		extra = append(extra, "--log-file", gf.LogFile)
	}
	if gf.Config != "" {
		extra = append(extra, "--config", gf.Config)
	}
	if len(extra) == 0 {
		return args
	}
	return append(extra, args...)
}

func resolveScanRoots(targetPath string, pathsRaw string, profile model.ScanProfile) ([]string, error) {
	if trimmed := strings.TrimSpace(pathsRaw); trimmed != "" {
		parts := strings.Split(trimmed, ",")
		return canonicalizePaths(parts)
	}
	if targetPath != "" && targetPath != "." {
		return canonicalizePaths([]string{targetPath})
	}
	switch profile {
	case model.ProfileDeveloper:
		return canonicalizePaths(defaultDeveloperRoots())
	case model.ProfileContainer, model.ProfileFullFS:
		return canonicalizePaths([]string{"/"})
	case model.ProfileRepo:
		fallthrough
	default:
		return canonicalizePaths([]string{targetPath})
	}
}

func defaultDeveloperRoots() []string {
	roots := make([]string, 0, 8)
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		roots = append(roots, home)
	}
	roots = append(roots, "/etc", "/usr/local", "/opt", "/var", "/tmp")
	return roots
}

func canonicalizePaths(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		p = model.ExpandHomePath(p)
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		abs = filepath.Clean(abs)
		if _, exists := seen[abs]; exists {
			continue
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}
	if len(out) == 0 {
		return nil, errors.New("no valid paths to scan")
	}
	return out, nil
}

func looksLikePath(s string) bool {
	if strings.ContainsAny(s, "/\\") || s == "." || s == ".." {
		return true
	}
	if strings.HasPrefix(s, "~") {
		return true
	}
	_, err := os.Stat(s)
	return err == nil
}

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
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

// emitReportTo renders the report to dest in the requested format.
func emitReportTo(dest io.Writer, stderr io.Writer, report model.Report, outputFormat model.OutputFormat) (model.Report, int) {
	switch outputFormat {
	case model.FormatJSON:
		enc := json.NewEncoder(dest)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(stderr, "json encode failed: %v\n", err)
			return model.Report{}, 1
		}
	case model.FormatSARIF:
		if err := reportpkg.WriteSARIFReport(dest, report); err != nil {
			fmt.Fprintf(stderr, "sarif encode failed: %v\n", err)
			return model.Report{}, 1
		}
	case model.FormatMarkdown:
		reportpkg.WriteMarkdown(dest, report)
	default:
		reportpkg.WriteTextReport(dest, report)
	}
	return report, 0
}

// emitReport writes the report to outPath when set, otherwise to stdout.
// The file write is atomic, so a consumer polling the path never reads a
// half-written report.
func emitReport(
	stdout io.Writer, stderr io.Writer, report model.Report,
	outputFormat model.OutputFormat, outPath string,
) (model.Report, int) {
	if strings.TrimSpace(outPath) == "" {
		return emitReportTo(stdout, stderr, report, outputFormat)
	}
	var buf bytes.Buffer
	if r, code := emitReportTo(&buf, stderr, report, outputFormat); code != 0 {
		return r, code
	}
	if err := reportpkg.WriteFileAtomic(outPath, buf.Bytes(), 0o644); err != nil {
		fmt.Fprintf(stderr, "failed to write report to %s: %v\n", outPath, err)
		return model.Report{}, 1
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

func skepticToolInformationURI() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	path := strings.TrimSpace(info.Main.Path)
	path = strings.TrimSuffix(path, "/cmd/skeptic")
	if strings.HasPrefix(path, "github.com/") {
		return "https://" + path
	}
	return ""
}

func resolveSARIFBasePath(explicit string, roots []string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return filepath.Abs(model.ExpandHomePath(explicit))
	}
	if len(roots) > 0 {
		start := roots[0]
		if info, err := os.Stat(start); err == nil && !info.IsDir() {
			start = filepath.Dir(start)
		}
		if root := findGitRoot(start); root != "" {
			return root, nil
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if root := findGitRoot(cwd); root != "" {
		return root, nil
	}
	return cwd, nil
}

func findGitRoot(start string) string {
	dir, err := filepath.Abs(start)
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
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

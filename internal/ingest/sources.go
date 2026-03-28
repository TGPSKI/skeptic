package ingest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

var errMaxFilesReached = errors.New("max files reached")

// ingestRepoSkipDirs mirrors cmd/skeptic main repo scan skips for directory walks.
var ingestRepoSkipDirs = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {}, "node_modules": {}, "vendor": {}, ".venv": {}, "venv": {},
	".tox": {}, "dist": {}, "build": {}, "out": {}, ".idea": {}, ".cursor": {}, ".pytest_cache": {}, ".cache": {},
}

func shouldSkipRepoDir(name string) bool {
	_, skip := ingestRepoSkipDirs[name]
	return skip
}

// ingestLikelyText matches main package behavior: empty files are treated as text.
func ingestLikelyText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	return model.LooksLikeText(data)
}

// ReadSourcesFile loads newline-delimited source definitions for bulk ingest runs.
func ReadSourcesFile(path string) ([]string, error) {
	abs, err := filepath.Abs(model.ExpandHomePath(path))
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, 32)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// SourceLoadOptions configures constraints for LoadSourceDocuments: size limits, timeouts, host allowlist, and logging.
type SourceLoadOptions struct {
	MaxSourceBytes int64
	MaxFilesPerDir int
	Timeout        time.Duration
	AllowHTTP      bool
	MaxRedirects   int
	AllowedHosts   []string
	Logger         *logging.Logger
}

// LoadSourceDocuments resolves and bounds source ingestion from mixed source types.
func LoadSourceDocuments(ctx context.Context, sources []string, opts SourceLoadOptions) ([]SourceDocument, []string, error) {
	allowedHostSet := make(map[string]struct{}, len(opts.AllowedHosts))
	for _, host := range opts.AllowedHosts {
		normalized := strings.ToLower(strings.TrimSpace(host))
		if normalized == "" {
			continue
		}
		allowedHostSet[normalized] = struct{}{}
	}
	client := &http.Client{
		Timeout: opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if opts.MaxRedirects >= 0 && len(via) > opts.MaxRedirects {
				return fmt.Errorf("redirect limit exceeded (%d)", opts.MaxRedirects)
			}
			if req.URL != nil {
				scheme := strings.ToLower(req.URL.Scheme)
				if scheme == "http" && !opts.AllowHTTP {
					return errors.New("redirect to http URL blocked")
				}
				if len(allowedHostSet) > 0 {
					host := strings.ToLower(req.URL.Hostname())
					if _, ok := allowedHostSet[host]; !ok {
						return fmt.Errorf("redirect host %q is not allowed", host)
					}
				}
			}
			return nil
		},
	}
	docs := make([]SourceDocument, 0, len(sources))
	warnings := make([]string, 0, 8)

	for _, source := range sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
			content, err := ReadURLSource(ctx, client, source, opts.MaxSourceBytes, opts.AllowHTTP, allowedHostSet)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", source, err))
				continue
			}
			if opts.Logger != nil {
				opts.Logger.Debugf("loaded URL source: %s", source)
			}
			docs = append(docs, SourceDocument{Source: source, Content: content})
			continue
		}

		path := model.ExpandHomePath(source)
		abs, err := filepath.Abs(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", source, err))
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", abs, err))
			continue
		}

		if info.Mode().IsRegular() {
			content, err := ReadLocalFileLimited(abs, opts.MaxSourceBytes)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", abs, err))
				continue
			}
			if opts.Logger != nil {
				opts.Logger.Debugf("loaded file source: %s", abs)
			}
			docs = append(docs, SourceDocument{Source: abs, Content: content})
			continue
		}
		if info.IsDir() {
			dirDocs, dirWarnings := ReadDirectorySource(abs, opts.MaxSourceBytes, opts.MaxFilesPerDir)
			docs = append(docs, dirDocs...)
			warnings = append(warnings, dirWarnings...)
			if opts.Logger != nil {
				opts.Logger.Debugf("loaded directory source: %s files=%d", abs, len(dirDocs))
			}
			continue
		}

		warnings = append(warnings, fmt.Sprintf("%s: unsupported source type", abs))
	}

	return docs, warnings, nil
}

// ReadURLSource fetches intel URLs with host allowlisting and redirect safeguards.
func ReadURLSource(
	ctx context.Context,
	client *http.Client,
	rawURL string,
	maxSourceBytes int64,
	allowHTTP bool,
	allowedHosts map[string]struct{},
) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("unsupported URL scheme")
	}
	if parsed.Scheme == "http" && !allowHTTP {
		return "", errors.New("http URLs are blocked by default; use --allow-http to enable")
	}
	if len(allowedHosts) > 0 {
		host := strings.ToLower(parsed.Hostname())
		if _, ok := allowedHosts[host]; !ok {
			return "", fmt.Errorf("host %q is not allowed", host)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: close HTTP response body: %v\n", cerr)
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("unexpected HTTP status: %s", resp.Status)
	}

	reader := io.LimitReader(resp.Body, maxSourceBytes)
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReadDirectorySource recursively ingests text-like files from a directory source.
func ReadDirectorySource(dir string, maxSourceBytes int64, maxFiles int) ([]SourceDocument, []string) {
	docs := make([]SourceDocument, 0, maxFiles)
	warnings := make([]string, 0, 8)
	count := 0

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", path, walkErr))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if shouldSkipRepoDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !IsLikelyTextByExt(path) {
			return nil
		}
		if count >= maxFiles {
			return errMaxFilesReached
		}
		content, err := ReadLocalFileLimited(path, maxSourceBytes)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		docs = append(docs, SourceDocument{Source: path, Content: content})
		count++
		return nil
	})
	if err != nil && !errors.Is(err, errMaxFilesReached) {
		warnings = append(warnings, fmt.Sprintf("%s: %v", dir, err))
	}
	return docs, warnings
}

// IsLikelyTextByExt fast-filters binary-heavy extensions to reduce noisy ingest.
func IsLikelyTextByExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".md", ".markdown", ".txt", ".html", ".htm", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".csv":
		return true
	default:
		return false
	}
}

// ReadLocalFileLimited reads local source files with explicit byte limits.
func ReadLocalFileLimited(path string, maxSourceBytes int64) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > maxSourceBytes {
		return "", fmt.Errorf("file too large (%d bytes > max %d)", info.Size(), maxSourceBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if !ingestLikelyText(data) {
		return "", errors.New("binary/non-text file")
	}
	return string(data), nil
}

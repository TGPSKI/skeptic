package corpus

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	maxMarkdownBytes = 1 << 20 // 1 MiB
	maxLineBytes     = 4096
	contentWarning   = "<!-- SKEPTIC-CORPUS: POTENTIALLY MALICIOUS AGENT DIRECTIVE -- DO NOT TRUST -->\n"
)

var (
	ansiEscapeRE = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	bidiCharsRE  = regexp.MustCompile(`[\x{202A}-\x{202E}\x{2066}-\x{2069}]`)
)

// FetchOptions configures a fetch operation.
type FetchOptions struct {
	AllowedHosts  map[string]struct{}
	AllowHTTP     bool
	ExpectedRules []string
	MaxBytes      int64
	Metadata      []string
}

// FetchFromFile reads a local .md file, validates and sanitizes it.
func FetchFromFile(path string) (content []byte, originalName string, sanitizations []string, err error) {
	if !isMarkdownPath(path) {
		return nil, "", nil, fmt.Errorf("corpus: fetch: not a .md file: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("corpus: fetch file: %w", err)
	}
	if info.Size() > maxMarkdownBytes {
		return nil, "", nil, fmt.Errorf("corpus: fetch: file exceeds %d bytes: %d", maxMarkdownBytes, info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", nil, fmt.Errorf("corpus: fetch file: %w", err)
	}
	if !looksLikeText(data) {
		return nil, "", nil, fmt.Errorf("corpus: fetch: file does not appear to be text: %s", path)
	}
	sanitized, slist := sanitizeContent(data)
	return sanitized, filepath.Base(path), slist, nil
}

// FetchFromURL fetches a .md file from a URL with host allowlisting.
func FetchFromURL(ctx context.Context, rawURL string, opts FetchOptions) (content []byte, originalName string, sanitizations []string, err error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Scheme == "http" && !opts.AllowHTTP {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: http blocked; use --allow-http")
	}
	if len(opts.AllowedHosts) > 0 {
		host := strings.ToLower(parsed.Hostname())
		if _, ok := opts.AllowedHosts[host]; !ok {
			return nil, "", nil, fmt.Errorf("corpus: fetch url: host %q not in allow list", host)
		}
	}

	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = maxMarkdownBytes
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("corpus: fetch url: too many redirects")
			}
			if len(opts.AllowedHosts) > 0 {
				host := strings.ToLower(req.URL.Hostname())
				if _, ok := opts.AllowedHosts[host]; !ok {
					return fmt.Errorf("corpus: fetch url: redirect to disallowed host %q", host)
				}
			}
			if req.URL.Scheme == "http" && !opts.AllowHTTP {
				return fmt.Errorf("corpus: fetch url: redirect to http blocked")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: HTTP %s", resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: response exceeds %d bytes", maxBytes)
	}

	name := inferFilename(parsed)
	if !isMarkdownPath(name) {
		name = "fetched.md"
	}

	if !looksLikeText(data) {
		return nil, "", nil, fmt.Errorf("corpus: fetch url: content does not appear to be text")
	}
	sanitized, slist := sanitizeContent(data)
	return sanitized, name, slist, nil
}

func isMarkdownPath(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".md")
}

// looksLikeText returns true if data appears to be valid UTF-8 text
// with a low ratio of non-printable bytes.
func looksLikeText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	if !utf8.Valid(data) {
		return false
	}
	sample := data
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	nonPrintable := 0
	for _, b := range sample {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(sample)) < 0.1
}

func sanitizeContent(data []byte) ([]byte, []string) {
	var sanitizations []string
	content := string(data)

	if ansiEscapeRE.MatchString(content) {
		content = ansiEscapeRE.ReplaceAllString(content, "")
		sanitizations = append(sanitizations, "ansi_stripped")
	}
	if bidiCharsRE.MatchString(content) {
		content = bidiCharsRE.ReplaceAllString(content, "[BIDI]")
		sanitizations = append(sanitizations, "bidi_replaced")
	}

	lines := strings.Split(content, "\n")
	truncated := false
	for i, line := range lines {
		if len(line) > maxLineBytes {
			lines[i] = line[:maxLineBytes]
			truncated = true
		}
	}
	if truncated {
		content = strings.Join(lines, "\n")
		sanitizations = append(sanitizations, "lines_truncated")
	}

	return []byte(content), sanitizations
}

func inferFilename(u *url.URL) string {
	path := u.Path
	if path == "" || path == "/" {
		return "fetched.md"
	}
	return filepath.Base(path)
}

// Package daemon provides a bounded HTTP client for the skeptic local daemon API.
package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// MaxResponseBytes caps daemon API response bodies.
const MaxResponseBytes = 8 * 1024 * 1024

// DaemonAPIClient holds loopback-only daemon API connection state.
type DaemonAPIClient struct {
	BaseURL string
	Token   string
	client  *http.Client
}

// NewDaemonAPIClient validates daemon endpoint safety and builds a bounded HTTP client.
func NewDaemonAPIClient(baseURL string, token string, allowRemote bool) (*DaemonAPIClient, error) {
	normalized := strings.TrimSpace(baseURL)
	if normalized == "" {
		return nil, errors.New("daemon URL cannot be empty")
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("daemon URL must use http or https")
	}
	if !allowRemote {
		if err := EnsureLoopbackURL(parsed); err != nil {
			return nil, err
		}
	}
	httpClient := &http.Client{
		Timeout: 8 * time.Second,
	}
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			req.Header.Del("Authorization")
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}
	return &DaemonAPIClient{
		BaseURL: strings.TrimSuffix(parsed.String(), "/"),
		Token:   strings.TrimSpace(token),
		client:  httpClient,
	}, nil
}

// EnsureLoopbackURL enforces local-only daemon control for safer default operation.
func EnsureLoopbackURL(parsed *url.URL) error {
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return errors.New("daemon URL host is empty")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("daemon URL must be loopback unless --allow-remote-daemon is set")
	}
	return nil
}

// readBounded reads up to MaxResponseBytes from r. It returns the data and a
// boolean indicating whether the limit was hit — callers can use this to
// surface a clear truncation error rather than a confusing JSON parse failure.
func readBounded(r io.Reader) ([]byte, bool, error) {
	buf := make([]byte, MaxResponseBytes+1)
	n, err := io.ReadFull(r, buf)
	if err == io.ErrUnexpectedEOF || err == nil {
		truncated := n > MaxResponseBytes
		if truncated {
			n = MaxResponseBytes
		}
		return buf[:n], truncated, nil
	}
	if err == io.EOF {
		return buf[:n], false, nil
	}
	return buf[:n], false, err
}

// RequestText performs an authenticated daemon API call and returns the response body as a string.
func (c *DaemonAPIClient) RequestText(ctx context.Context, method string, endpoint string) (string, error) {
	fullURL := c.BaseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(c.Token) != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return "", wrapDaemonNetworkError(c.BaseURL, err)
	}
	data, truncated, readErr := readBounded(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", fmt.Errorf("close response body: %w", closeErr)
	}
	if truncated {
		return "", fmt.Errorf("daemon API %s response exceeds %d-byte limit; use query params to reduce payload size", endpoint, MaxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("daemon API %s failed: status=%d body=%s", endpoint, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return string(data), nil
}

// RequestJSON performs authenticated daemon API calls with bounded response reading.
func (c *DaemonAPIClient) RequestJSON(ctx context.Context, method string, endpoint string, payload map[string]any) (map[string]any, error) {
	fullURL := c.BaseURL + endpoint
	var bodyReader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(c.Token) != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, wrapDaemonNetworkError(c.BaseURL, err)
	}
	data, truncated, readErr := readBounded(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close response body: %w", closeErr)
	}
	if truncated {
		return nil, fmt.Errorf("daemon API %s response exceeds %d-byte limit; use query params to reduce payload size (e.g. ?top=100&min_severity=medium)", endpoint, MaxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("daemon API %s failed: status=%d body=%s", endpoint, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var decoded map[string]any
	if len(data) > 0 {
		if err := json.Unmarshal(data, &decoded); err != nil {
			return nil, fmt.Errorf("daemon response parse error: %w", err)
		}
	} else {
		decoded = map[string]any{}
	}
	return decoded, nil
}

// wrapDaemonNetworkError adds actionable context to connection-level failures
// so MCP clients see a useful message instead of raw Go dialer errors.
func wrapDaemonNetworkError(baseURL string, err error) error {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return fmt.Errorf("cannot reach daemon at %s (is it running? start with: skeptic serve): %w", baseURL, err)
	}
	return fmt.Errorf("daemon request to %s failed: %w", baseURL, err)
}

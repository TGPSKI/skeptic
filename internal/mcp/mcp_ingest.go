package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
)

func handleIngestURLToRulepack(args map[string]any, state *MCPServerState) (map[string]any, error) {
	if !state.AllowIngest {
		return nil, errors.New("ingest tool disabled by server configuration")
	}
	sourceURL := strings.TrimSpace(anyToString(args["source_url"]))
	if sourceURL == "" {
		return nil, errors.New("source_url is required")
	}
	if err := CheckMCPIngestHostAllowed(sourceURL, state.IngestAllowedHosts); err != nil {
		return nil, err
	}
	if state.RequireIngestApproval {
		outFile := anyToString(args["out_file"])
		state.PendingIngest = &PendingIngestRequest{
			URL:     sourceURL,
			OutFile: outFile,
			Args:    args,
		}
		return applyMCPToolNonce(mcpToolSuccess(map[string]any{
			"status":   "pending_approval",
			"url":      sourceURL,
			"out_file": outFile,
			"message":  "Ingest requires approval. Call skeptic_approve_ingest to proceed.",
		}), args), nil
	}
	result, err := MCPIngestURLToRulepack(context.Background(), args, state.RulesOutDir, state.RunIngest)
	if err != nil {
		return nil, err
	}
	return applyMCPToolNonce(mcpToolSuccess(result), args), nil
}

func handleApproveIngest(state *MCPServerState) (map[string]any, error) {
	if state.PendingIngest == nil {
		return nil, errors.New("no pending ingest request to approve")
	}
	pending := state.PendingIngest
	if err := CheckMCPIngestHostAllowed(pending.URL, state.IngestAllowedHosts); err != nil {
		return nil, err
	}
	state.PendingIngest = nil
	result, err := MCPIngestURLToRulepack(context.Background(), pending.Args, state.RulesOutDir, state.RunIngest)
	if err != nil {
		return nil, err
	}
	return applyMCPToolNonce(mcpToolSuccess(result), pending.Args), nil
}

// MCPIngestURLToRulepack invokes the ingest pipeline with safe defaults.
func MCPIngestURLToRulepack(ctx context.Context, args map[string]any, rulesOutDir string, runIngest RunIngestFunc) (map[string]any, error) {
	sourceURL := strings.TrimSpace(anyToString(args["source_url"]))
	if sourceURL == "" {
		return nil, errors.New("source_url is required")
	}
	parsedURL, err := url.Parse(sourceURL)
	if err != nil {
		return nil, fmt.Errorf("invalid source_url: %w", err)
	}
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return nil, errors.New("source_url must use http or https")
	}

	outPath, err := ResolveRulesOutputPath(anyToString(args["out_file"]), rulesOutDir)
	if err != nil {
		return nil, err
	}
	allowHost := strings.TrimSpace(anyToString(args["allow_host"]))
	if allowHost == "" {
		allowHost = parsedURL.Hostname()
	}

	ingestArgs := []string{
		"--source", sourceURL,
		"--out", outPath,
		"--allow-host", allowHost,
		"--rule-quality", defaultString(anyToString(args["rule_quality"]), "strict"),
		"--min-severity", defaultString(anyToString(args["min_severity"]), "medium"),
		"--ecosystems", defaultString(anyToString(args["ecosystems"]), "general,pypi,npm,github-actions,container,mcp,agent-skills,go,cargo"),
	}
	if anyToBool(args["allow_http"]) {
		ingestArgs = append(ingestArgs, "--allow-http")
	}

	var outBuf, errBuf bytes.Buffer
	exitCode := runIngest(ctx, ingestArgs, &outBuf, &errBuf)
	if exitCode != 0 {
		return nil, fmt.Errorf("ingest failed with exit code %d: %s", exitCode, strings.TrimSpace(errBuf.String()))
	}

	return map[string]any{
		"out_file": outPath,
		"stdout":   strings.TrimSpace(outBuf.String()),
		"stderr":   strings.TrimSpace(errBuf.String()),
	}, nil
}

// ResolveRulesOutputPath prevents path traversal and keeps generated packs in the configured output directory.
func ResolveRulesOutputPath(outFile string, rulesOutDir string) (string, error) {
	baseDir, err := filepath.Abs(model.ExpandHomePath(rulesOutDir))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return "", err
	}

	fileName := strings.TrimSpace(outFile)
	if fileName == "" {
		fileName = fmt.Sprintf("ingested-rules-%s.json", time.Now().UTC().Format("20060102-150405"))
	}
	if strings.Contains(fileName, string(os.PathSeparator)) {
		fileName = filepath.Base(fileName)
	}
	if !strings.HasSuffix(strings.ToLower(fileName), ".json") {
		fileName += ".json"
	}
	absOut := filepath.Join(baseDir, fileName)
	absOut, err = filepath.Abs(absOut)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(baseDir, absOut)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "..") {
		return "", errors.New("output path escapes rules output directory")
	}
	return absOut, nil
}

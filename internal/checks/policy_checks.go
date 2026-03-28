package checks

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

var (
	reWorkflowUses          = regexp.MustCompile(`(?i)\buses:\s*([a-z0-9_.-]+/[a-z0-9_.-]+)@([^\s#]+)`)
	reWorkflowDockerUses    = regexp.MustCompile(`(?i)\buses:\s*docker://([^\s#]+)`)
	reWorkflowPermissions   = regexp.MustCompile(`(?i)\bpermissions\s*:\s*(write-all|\{[^}]*\b(write|admin)\b[^}]*\})`)
	reWorkflowIDTokenWrite  = regexp.MustCompile(`(?i)\bid-token\s*:\s*write\b`)
	reWorkflowContentsWrite = regexp.MustCompile(`(?i)\bcontents\s*:\s*write\b`)
	reSHA40                 = regexp.MustCompile(`^[a-f0-9]{40}$`)
	rePipRemoteInstall      = regexp.MustCompile(`(?i)\bpip(?:3)?\s+install\b.{0,200}(https?://|git\+https?://)`)
	rePackageRangeSpec      = regexp.MustCompile(`(?i)"[^"]+"\s*:\s*"(?:\^|~|>|<|\*|latest|next)`)
	reDockerFrom            = regexp.MustCompile(`(?i)^\s*from\s+([a-z0-9._/\-:]+)`)
	reScopeWildcard         = regexp.MustCompile(`(?i)\b(scope|sub|subject|subjects)\b.{0,120}(\*|repo:\*|system:serviceaccount:\*)`)
	reOIDCFederation        = regexp.MustCompile(`(?i)(token\.actions\.githubusercontent\.com|oidc|federated|workload identity)`)
)

// RunPolicyChecks performs file-aware trust and integrity checks beyond single-rule matching.
//
//nolint:gocyclo // multi-file-type policy dispatch is inherently branchy
func RunPolicyChecks(absPath string, fileLabel string, lines []string, content string, redactSecrets bool) []model.Finding {
	lowerPath := strings.ToLower(filepath.ToSlash(absPath))
	lowerContent := strings.ToLower(content)
	findings := make([]model.Finding, 0, 8)

	add := func(ruleID, title, description, category, mitre string, severity model.Severity, line int, match string) {
		findings = append(findings, model.Finding{
			RuleID:          ruleID,
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           title,
			Description:     description,
			Category:        category,
			Mitre:           mitre,
			Severity:        severity,
			File:            fileLabel,
			Line:            line,
			Match:           security.SanitizeMatch(match, redactSecrets),
		})
	}

	isWorkflow := strings.Contains(lowerPath, "/.github/workflows/") &&
		(strings.HasSuffix(lowerPath, ".yml") || strings.HasSuffix(lowerPath, ".yaml"))
	if isWorkflow {
		for i, line := range lines {
			matches := reWorkflowUses.FindStringSubmatch(line)
			if len(matches) == 3 {
				ref := strings.TrimSpace(strings.ToLower(matches[2]))
				if !reSHA40.MatchString(ref) {
					add(
						"POL-GHA-001",
						"GitHub Action reference is not commit SHA pinned",
						"Workflow action references should be pinned to immutable commit SHAs to reduce tag-poisoning and mutable-ref supply chain risk.",
						"policy-scm-trust",
						"T1195.002",
						model.SeverityHigh,
						i+1,
						line,
					)
				}
			}
			dockerMatches := reWorkflowDockerUses.FindStringSubmatch(line)
			if len(dockerMatches) == 2 {
				image := strings.TrimSpace(dockerMatches[1])
				if !strings.Contains(image, "@sha256:") {
					add(
						"POL-GHA-002",
						"Workflow docker action lacks immutable digest pin",
						"Workflow docker action references should include image digest pinning to prevent mutable tag drift.",
						"policy-scm-trust",
						"T1195.002",
						model.SeverityMedium,
						i+1,
						line,
					)
				}
			}
			if reWorkflowPermissions.MatchString(line) {
				add(
					"POL-GHA-003",
					"Workflow permissions appear overly broad",
					"Detected broad workflow permissions. Narrow token scopes and use least privilege for CI identities.",
					"policy-machine-identity",
					"T1528",
					model.SeverityHigh,
					i+1,
					line,
				)
			}
		}
		if reWorkflowIDTokenWrite.MatchString(content) && reWorkflowContentsWrite.MatchString(content) {
			add(
				"POL-GHA-004",
				"Workflow grants both OIDC and repository write permissions",
				"Combining id-token:write with contents:write increases blast radius if workflow execution is compromised.",
				"policy-machine-identity",
				"T1550.001",
				model.SeverityHigh,
				0,
				"id-token: write + contents: write",
			)
		}
	}

	baseName := strings.ToLower(filepath.Base(lowerPath))
	isRequirements := strings.HasPrefix(baseName, "requirements") && strings.HasSuffix(baseName, ".txt")
	if isRequirements {
		hasPackagePins := false
		hasHashes := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.Contains(trimmed, "--hash=") {
				hasHashes = true
			}
			if strings.Contains(trimmed, "==") {
				hasPackagePins = true
			}
		}
		if hasPackagePins && !hasHashes && !strings.Contains(lowerContent, "--require-hashes") {
			add(
				"POL-PIP-001",
				"Python requirements are not hash pinned",
				"requirements file contains package pins without hashes; use --require-hashes or pinned wheel hashes to reduce package tampering risk.",
				"policy-dependency-integrity",
				"T1195.002",
				model.SeverityMedium,
				0,
				fileLabel,
			)
		}
	}

	for i, line := range lines {
		if rePipRemoteInstall.MatchString(line) {
			add(
				"POL-PIP-002",
				"Remote pip install source in script or config",
				"Detected direct remote pip install source. Prefer vetted mirrors, exact hashes, and pre-reviewed dependency lock inputs.",
				"policy-dependency-integrity",
				"T1195.002",
				model.SeverityHigh,
				i+1,
				line,
			)
		}
	}

	if strings.HasSuffix(lowerPath, "package.json") && strings.Contains(lowerContent, "\"dependencies\"") {
		if match := rePackageRangeSpec.FindString(content); strings.TrimSpace(match) != "" {
			add(
				"POL-NPM-001",
				"Node dependencies include mutable semver ranges",
				"Dependency ranges (e.g. ^, ~, latest) allow unreviewed updates. Prefer lockfiles and stricter pinning for critical workloads.",
				"policy-dependency-integrity",
				"T1195.002",
				model.SeverityMedium,
				0,
				match,
			)
		}
	}

	isDockerfile := strings.HasSuffix(lowerPath, "/dockerfile") || strings.HasSuffix(lowerPath, ".dockerfile") || baseName == "dockerfile"
	if isDockerfile {
		for i, line := range lines {
			matches := reDockerFrom.FindStringSubmatch(strings.TrimSpace(line))
			if len(matches) == 2 {
				image := matches[1]
				if strings.Contains(image, ":") && !strings.Contains(image, "@sha256:") {
					add(
						"POL-CNT-001",
						"Docker base image is not digest pinned",
						"Base image references with mutable tags can drift. Pin to image digest for stronger reproducibility and trust.",
						"policy-scm-trust",
						"T1195.002",
						model.SeverityMedium,
						i+1,
						line,
					)
				}
			}
		}
	}

	if reOIDCFederation.MatchString(content) && reScopeWildcard.MatchString(content) {
		add(
			"POL-CLOUDID-001",
			"Federated identity trust policy appears wildcarded",
			"OIDC or federated trust policy appears to allow wildcard subjects/scopes. Restrict trust claims to expected repositories/workloads.",
			"policy-machine-identity",
			"T1528",
			model.SeverityHigh,
			0,
			findPolicyTrustSnippet(content),
		)
	}

	return findings
}

// findPolicyTrustSnippet selects a representative wildcard trust line for finding context.
func findPolicyTrustSnippet(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if reScopeWildcard.MatchString(line) {
			return strings.TrimSpace(line)
		}
	}
	return strings.TrimSpace(fmt.Sprintf("wildcard trust signal in content (%d bytes)", len(content)))
}

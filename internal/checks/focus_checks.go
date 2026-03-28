package checks

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

var (
	reMachineRoleBroad      = regexp.MustCompile(`(?i)\b(Owner|Contributor|cluster-admin|AdministratorAccess|iam:\*)\b`)
	reMachineClientSecret   = regexp.MustCompile(`(?i)\b(client_secret|app_role_secret|service_principal_secret)\b`)
	reMachineGraphAPI       = regexp.MustCompile(`(?i)\b(graph\.microsoft\.com|oauth2/v2\.0/token|grant_type=client_credentials)\b`)
	reMachineTokenKey       = regexp.MustCompile(`(?i)\b(access_token|refresh_token|authorization:\s*bearer)\b`)
	reMachineVaultPath      = regexp.MustCompile(`(?i)\b(vault|secret(s)?manager|kv-v2|approle)\b`)
	reAIVectorDB            = regexp.MustCompile(`(?i)\b(qdrant|weaviate|milvus|chroma|pinecone|faiss)\b`)
	reAIVectorNoAuth        = regexp.MustCompile(`(?i)\b(auth|authentication|api[_-]?key|token)\b.{0,40}\b(false|off|disabled|none)\b`)
	reAIAutoApprove         = regexp.MustCompile(`(?i)(auto.?approve|approval[_-]?mode)\s*[:=]\s*(none|auto|always)`)
	reAIPromptTelemetry     = regexp.MustCompile(`(?i)\b(log_prompts|store_prompts|prompt_logging|save_conversation|store_responses)\b.{0,40}\b(true|on|enabled)\b`)
	reAIPublicInferenceBind = regexp.MustCompile(`(?i)\b(0\.0\.0\.0|::)\b.{0,80}\b(6333|8000|8080|11434)\b`)
	reMIDOIDCContext        = regexp.MustCompile(`(?i)(oidc|openid)`)
	reMIDSPIFFEWildcard     = regexp.MustCompile(`(?i)spiffe://[^/]*\*`)
	reMIDStaticTokenEnv     = regexp.MustCompile(`(?i)(TOKEN|API_KEY|SECRET)=\S{20,}`)
	reOIDCYAMLAudField      = regexp.MustCompile(`(?i)\baud\s*:`)
	reAIWVectorBindAll      = regexp.MustCompile(`(?is)(qdrant|milvus|pinecone|weaviate|chromadb|chroma).*0\.0\.0\.0`)
	reAIWEmbeddingPerm777   = regexp.MustCompile(`(?i)(embeddings?_path|vector_store_path).*(0o?777|\b777\b)`)
	reK8sServiceAccountKind = regexp.MustCompile(`(?i)kind:\s*ServiceAccount`)
	reK8sAutomountDisabled  = regexp.MustCompile(`(?i)automountServiceAccountToken:\s*false`)
	reAIWPromptLogEnabled   = regexp.MustCompile(`(?i)(log_prompts|prompt_logging|store_prompts)\s*[:=]\s*(true|1|yes)`)
)

// RunFocusChecks adds domain-specific checks for machine identity and AI workload modes.
func RunFocusChecks(absPath string, fileLabel string, lines []string, content string, redactSecrets bool, mode model.ThreatMode) []model.Finding {
	findings := make([]model.Finding, 0, 8)
	if mode == model.ThreatModeAll || mode == model.ThreatModeMachineIdentity {
		findings = append(findings, runMachineIdentityChecks(absPath, fileLabel, lines, content, redactSecrets)...)
	}
	if mode == model.ThreatModeAll || mode == model.ThreatModeAIWorkload {
		findings = append(findings, runAIWorkloadChecks(absPath, fileLabel, lines, content, redactSecrets)...)
	}
	return findings
}

func runMachineIdentityChecks(absPath, fileLabel string, lines []string, content string, redactSecrets bool) []model.Finding {
	findings := make([]model.Finding, 0, 8)
	lowerPath := strings.ToLower(filepath.ToSlash(absPath))

	add := func(ruleID, title, description, category, mitre string, severity model.Severity, line int, match string) {
		findings = append(findings, model.Finding{
			RuleID:          ruleID,
			ConfidenceClass: model.ConfidenceHeuristic,
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

	for i, line := range lines {
		if reMachineRoleBroad.MatchString(line) && (strings.Contains(strings.ToLower(line), "role") || strings.Contains(strings.ToLower(line), "policy")) {
			add(
				"MID-001",
				"Over-privileged machine identity role assignment",
				"Detected broad role/policy assignment that increases machine-identity blast radius if credentials are compromised.",
				"machine-identity",
				"T1098",
				model.SeverityHigh,
				i+1,
				line,
			)
		}
		if reMachineClientSecret.MatchString(line) && strings.Contains(line, ":") {
			add(
				"MID-002",
				"Static machine identity secret in config-like content",
				"Detected static client or service principal secret material in local config/script content.",
				"machine-identity",
				"T1552.001",
				model.SeverityHigh,
				i+1,
				line,
			)
		}
	}
	if reMachineGraphAPI.MatchString(content) && reMachineTokenKey.MatchString(content) {
		add(
			"MID-003",
			"Graph API or OAuth client-credential token flow detected",
			"Detected machine-to-machine token grant patterns. Verify least privilege, token lifetime, and strict audience binding.",
			"machine-identity",
			"T1528",
			model.SeverityMedium,
			0,
			"machine identity token grant flow",
		)
	}
	if reMachineVaultPath.MatchString(content) && reMachineTokenKey.MatchString(content) {
		add(
			"MID-004",
			"Secret manager context with direct token material",
			"Detected token-bearing content near secret-management context; review for accidental credential leakage paths.",
			"machine-identity",
			"T1552.001",
			model.SeverityMedium,
			0,
			fileLabel,
		)
	}
	if reMIDOIDCContext.MatchString(content) && strings.Contains(strings.ToLower(content), "issuer") && !HasOIDCAudienceBinding(content) {
		add(
			"MID-101",
			"OIDC configuration missing audience constraint",
			"OIDC/OpenID context includes an issuer but no audience (aud) binding; tokens may be accepted by unintended relying parties.",
			"machine-identity",
			"T1550",
			model.SeverityHigh,
			0,
			fileLabel,
		)
	}
	if reMIDSPIFFEWildcard.MatchString(content) {
		add(
			"MID-102",
			"SPIFFE ID or trust domain uses a wildcard",
			"Wildcard in SPIFFE trust domain or path can broaden workload identity acceptance beyond intended services.",
			"machine-identity",
			"T1550",
			model.SeverityHigh,
			0,
			"spiffe wildcard",
		)
	}
	if IsYAMLPath(lowerPath) && reK8sServiceAccountKind.MatchString(content) &&
		!reK8sAutomountDisabled.MatchString(content) {
		add(
			"MID-103",
			"Kubernetes ServiceAccount without automount token disabled",
			"ServiceAccount manifests should set automountServiceAccountToken: false unless a mounted token is explicitly required.",
			"machine-identity",
			"T1552",
			model.SeverityMedium,
			0,
			fileLabel,
		)
	}
	if IsShellLikeOrEnvPath(lowerPath) && reMIDStaticTokenEnv.MatchString(content) {
		line := 0
		match := "static token-like env assignment"
		for i, lineStr := range lines {
			if reMIDStaticTokenEnv.MatchString(lineStr) {
				line = i + 1
				match = lineStr
				break
			}
		}
		add(
			"MID-104",
			"Long static token or secret in shell/env-like file",
			"Detected TOKEN/API_KEY/SECRET-style assignment with a long value; prefer short-lived credentials and secret managers.",
			"machine-identity",
			"T1552.001",
			model.SeverityHigh,
			line,
			match,
		)
	}
	return findings
}

func runAIWorkloadChecks(absPath, fileLabel string, lines []string, content string, redactSecrets bool) []model.Finding {
	findings := make([]model.Finding, 0, 8)
	lowerPath := strings.ToLower(filepath.ToSlash(absPath))

	add := func(ruleID, title, description, category, mitre string, severity model.Severity, line int, match string) {
		findings = append(findings, model.Finding{
			RuleID:          ruleID,
			ConfidenceClass: model.ConfidenceHeuristic,
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

	for i, line := range lines {
		lineLower := strings.ToLower(line)
		if reAIPromptTelemetry.MatchString(line) {
			add(
				"AIW-001",
				"AI prompt/response telemetry appears persisted",
				"Detected prompt/response logging flags that can centralize sensitive model inputs and outputs.",
				"ai-workload",
				"T1552",
				model.SeverityMedium,
				i+1,
				line,
			)
		}
		if reAIAutoApprove.MatchString(line) && (strings.Contains(lineLower, "tool") || strings.Contains(lineLower, "action") || strings.Contains(lineLower, "agent")) {
			add(
				"AIW-002",
				"AI agent/tool approval mode appears permissive",
				"Detected auto-approval configuration for agent/tool actions. Require explicit approval for high-risk operations.",
				"ai-workload",
				"T1565",
				model.SeverityHigh,
				i+1,
				line,
			)
		}
		if reAIPublicInferenceBind.MatchString(line) && (strings.Contains(lineLower, "serve") || strings.Contains(lineLower, "listen") || strings.Contains(lineLower, "bind")) {
			add(
				"AIW-003",
				"AI service appears bound on public or broad interface",
				"Detected broad bind/listen configuration for AI services. Restrict exposure and require authenticated front doors.",
				"ai-workload",
				"T1190",
				model.SeverityMedium,
				i+1,
				line,
			)
		}
	}
	if reAIVectorDB.MatchString(content) && reAIVectorNoAuth.MatchString(content) {
		add(
			"AIW-004",
			"Vector database appears configured without authentication",
			"Detected vector database context with disabled auth semantics, increasing poisoning and data-exposure risk.",
			"ai-workload",
			"T1190",
			model.SeverityHigh,
			0,
			fileLabel,
		)
	}
	if strings.Contains(lowerPath, "openapi") || strings.Contains(lowerPath, "swagger") {
		if strings.Contains(strings.ToLower(content), "agent") || strings.Contains(strings.ToLower(content), "model") {
			add(
				"AIW-005",
				"AI workload API surface definition discovered",
				"API schema for AI/agent services found. Run BOLA/BFLA authorization checks and machine identity review against these endpoints.",
				"ai-workload",
				"T1190",
				model.SeverityInfo,
				0,
				fileLabel,
			)
		}
	}
	if IsDockerComposeOrAIConfigPath(lowerPath) && reAIWVectorBindAll.MatchString(content) {
		add(
			"AIW-101",
			"Vector store service bound to all interfaces",
			"Vector DB or embedding service appears advertised on 0.0.0.0; restrict bind addresses and enforce authentication.",
			"ai-workload",
			"T1190",
			model.SeverityHigh,
			0,
			fileLabel,
		)
	}
	if AIW102ModelServingWithoutAuth(content) {
		add(
			"AIW-102",
			"Model serving endpoint without obvious auth controls",
			"Model serving or inference configuration mentions port exposure without auth, token, or key semantics in the same file.",
			"ai-workload",
			"T1190",
			model.SeverityHigh,
			0,
			fileLabel,
		)
	}
	if AIW103PromptLogNoRetention(content) {
		add(
			"AIW-103",
			"Prompt logging enabled without retention or TTL",
			"Prompt or conversation logging is enabled without nearby retention/TTL controls; define data minimization and lifecycle.",
			"ai-workload",
			"T1552",
			model.SeverityMedium,
			0,
			fileLabel,
		)
	}
	if reAIWEmbeddingPerm777.MatchString(content) {
		add(
			"AIW-104",
			"Embedding or vector store path with world-readable permissions",
			"Embedding storage path is configured with 0777 or world-readable semantics; tighten filesystem permissions.",
			"ai-workload",
			"T1552",
			model.SeverityHigh,
			0,
			fileLabel,
		)
	}
	return findings
}

// HasOIDCAudienceBinding reports whether content mentions an OIDC audience (YAML aud:, JSON "aud", or "audience").
func HasOIDCAudienceBinding(content string) bool {
	lower := strings.ToLower(content)
	if strings.Contains(lower, "audience") {
		return true
	}
	if strings.Contains(content, `"aud"`) || strings.Contains(content, `'aud'`) {
		return true
	}
	return reOIDCYAMLAudField.MatchString(content)
}

// IsYAMLPath is true for .yaml/.yml paths so Kubernetes and structured-config checks apply.
func IsYAMLPath(lower string) bool {
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}

// IsShellLikeOrEnvPath matches shell scripts, env files, and Dockerfiles where static secrets are common.
func IsShellLikeOrEnvPath(lower string) bool {
	switch {
	case strings.HasSuffix(lower, ".sh"), strings.HasSuffix(lower, ".bash"), strings.HasSuffix(lower, ".zsh"):
		return true
	case strings.HasSuffix(lower, ".env"), strings.HasSuffix(lower, ".env.local"), strings.HasSuffix(lower, ".envrc"):
		return true
	case strings.HasSuffix(lower, "dockerfile"), strings.Contains(lower, "dockerfile"):
		return true
	case strings.HasSuffix(lower, ".profile"), strings.HasSuffix(lower, ".bashrc"), strings.HasSuffix(lower, ".zshrc"):
		return true
	default:
		return false
	}
}

// IsDockerComposeOrAIConfigPath is true for compose files and common AI stack config extensions.
func IsDockerComposeOrAIConfigPath(lower string) bool {
	if strings.Contains(lower, "docker-compose") || strings.Contains(lower, "compose.yaml") || strings.Contains(lower, "compose.yml") {
		return true
	}
	for _, suf := range []string{".yaml", ".yml", ".conf", ".toml", ".json", ".env"} {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

// AIW102ModelServingWithoutAuth detects model serving or inference with a port but no auth/token/key hints in the same blob.
func AIW102ModelServingWithoutAuth(content string) bool {
	lower := strings.ToLower(content)
	hasPort := strings.Contains(lower, "port")
	hasServing := strings.Contains(lower, "model_server") ||
		(strings.Contains(lower, "serving") && hasPort) ||
		(strings.Contains(lower, "inference") && hasPort)
	if !hasServing {
		return false
	}
	if strings.Contains(lower, "auth") || strings.Contains(lower, "token") || strings.Contains(lower, "key") {
		return false
	}
	return true
}

// AIW103PromptLogNoRetention is true when prompt logging is enabled but no TTL or retention controls appear nearby.
func AIW103PromptLogNoRetention(content string) bool {
	lower := strings.ToLower(content)
	if !reAIWPromptLogEnabled.MatchString(content) {
		return false
	}
	if strings.Contains(lower, "ttl") || strings.Contains(lower, "retention") {
		return false
	}
	return true
}

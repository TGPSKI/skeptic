package ingest

import (
	"encoding/csv"
	"fmt"
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

var (
	reURL = regexp.MustCompile(`https?://[^\s"'<>]+`)
	reIP  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b`)
	// Conservative domain extractor, used after URL extraction.
	reDomain  = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
	reSHA256  = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	reSHA1    = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	reAction  = regexp.MustCompile(`\b[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+@[a-zA-Z0-9._/-]+\b`)
	rePyReq   = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9._-]{1,80})\s*(==|===|~=|>=|<=)\s*([0-9]+(?:\.[0-9]+){1,3}[a-z0-9.\-+]*)\b`)
	rePyText  = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9._-]{1,80})\s+v([0-9]+(?:\.[0-9]+){1,3}[a-z0-9.\-+]*)\b`)
	reNpmPkg  = regexp.MustCompile(`(?i)\b(@[a-z0-9._-]+/[a-z0-9._-]+)\b`)
	reGoMod   = regexp.MustCompile(`\b([a-z0-9][a-z0-9._-]+(?:/[a-z0-9._-]+)+)\s+v([0-9]+\.[0-9]+\.[0-9]+[a-z0-9.\-+]*)\b`)
	reCargo   = regexp.MustCompile(`(?i)\b([a-z0-9][a-z0-9_-]{1,80})\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+[a-z0-9.\-+]*)"\b`)
	reImage   = regexp.MustCompile(`\b([a-z0-9._-]+(?:/[a-z0-9._-]+)+:[a-zA-Z0-9._-]+)\b`)
	reHTMLTag = regexp.MustCompile(`<[^>]+>`)
)

var riskKeywords = []string{
	"malicious",
	"poison",
	"poisoning",
	"prompt injection",
	"tool poisoning",
	"memory poisoning",
	"backdoor",
	"credential",
	"stealer",
	"stolen",
	"compromise",
	"compromised",
	"c2",
	"command and control",
	"exfil",
	"exfiltration",
	"ioc",
	"indicator of compromise",
	"payload",
	"worm",
	"rug pull",
	"shadowing",
	"hijack",
	"ssrf",
	"remote code execution",
	"unauthorized",
	"attack",
	"threat",
	"tag poisoning",
	"force-push",
	"runner memory",
	"ebpf",
	"rootkit",
	"typosquat",
	"false positive poisoning",
	"context bypass",
	"shadow ai",
	"ephemeral workload",
	"serverless",
	"shadow api",
	"zombie api",
}

var strongRiskKeywords = []string{
	"malicious",
	"compromised",
	"c2",
	"command and control",
	"ioc",
	"indicator of compromise",
	"exfil",
	"stealer",
	"backdoor",
	"payload",
	"worm",
	"rug pull",
	"shadowing",
	"hijack",
	"tag poisoning",
	"runner memory",
	"ebpf",
	"rootkit",
	"typosquat",
	"context bypass",
}

var suspiciousCommandPatterns = []struct {
	id          string
	title       string
	description string
	severity    model.Severity
	pattern     string
	mitre       string
}{
	{
		id:          "INGEST-CMD-RCE",
		title:       "Suspicious remote script execution pipeline",
		description: "Detected curl/wget pipeline into shell interpreter in threat-intel source.",
		severity:    model.SeverityCritical,
		pattern:     `(?i)\b(curl|wget)\b.{0,200}\|\s*(bash|sh|zsh|source)\b`,
		mitre:       "T1059",
	},
	{
		id:          "INGEST-CMD-OBF",
		title:       "Obfuscated command decode chain",
		description: "Detected base64/eval decode chain in threat-intel source.",
		severity:    model.SeverityHigh,
		pattern:     `(?i)(eval\s*\(.{0,120}base64\s*-d|base64\s*-d.{0,80}\|\s*(bash|sh|zsh)|powershell.{0,40}(-enc|-encodedcommand)\b)`,
		mitre:       "T1027",
	},
	{
		id:          "INGEST-CMD-DESTRUCTIVE",
		title:       "Destructive shell command marker",
		description: "Detected destructive command marker (rm -rf/sudo destructive flow) in threat-intel source.",
		severity:    model.SeverityHigh,
		pattern:     `(?i)(\brm\s+-rf\b|\bsudo\b.{0,80}\brm\b)`,
		mitre:       "T1562",
	},
	{
		id:          "INGEST-CMD-TAGPOISON",
		title:       "Mutable tag poisoning operation marker",
		description: "Detected git operations that can rewrite trusted tags in CI/CD flows.",
		severity:    model.SeverityHigh,
		pattern:     `(?i)(git\s+tag\s+-f\b|git\s+push\b.{0,80}--force.{0,40}--tags\b|git\s+push\b.{0,120}:refs/tags/)`,
		mitre:       "T1195.002",
	},
	{
		id:          "INGEST-CMD-EBPF",
		title:       "eBPF load/attach operation marker",
		description: "Detected eBPF load/attach command/API markers relevant to runtime telemetry tampering.",
		severity:    model.SeverityHigh,
		pattern:     `(?i)(bpftool\s+(prog|map|net)\b|tc\s+filter\s+add.{0,120}\bbpf\b|bpf\(\s*BPF_PROG_LOAD)`,
		mitre:       "T1562.001",
	},
}

// containsRiskKeyword identifies broad risk vocabulary within source lines.
func containsRiskKeyword(lineLower string) bool {
	for _, keyword := range riskKeywords {
		if strings.Contains(lineLower, keyword) {
			return true
		}
	}
	return false
}

// containsStrongRiskKeyword identifies high-confidence attack vocabulary.
func containsStrongRiskKeyword(lineLower string) bool {
	for _, keyword := range strongRiskKeywords {
		if strings.Contains(lineLower, keyword) {
			return true
		}
	}
	return false
}

// AddGeneralIOCLineRules emits generic IOC and suspicious command rules from a source line.
func AddGeneralIOCLineRules(c *GeneratedRuleCollector, line string, risky bool, strongRisk bool, _ string, _ int) {
	for _, hash := range reSHA256.FindAllString(line, -1) {
		c.AddRule(NewLiteralRule("ingested-ioc", "SHA256 IOC from threat intelligence", "T1195.002", model.SeverityCritical, hash, true))
	}
	for _, hash := range reSHA1.FindAllString(line, -1) {
		c.AddRule(NewLiteralRule("ingested-ioc", "SHA1 IOC from threat intelligence", "T1195.002", model.SeverityHigh, hash, true))
	}
	for _, ip := range reIP.FindAllString(line, -1) {
		ip = CleanIndicator(ip)
		sev := model.SeverityMedium
		if strongRisk {
			sev = model.SeverityHigh
		}
		c.AddRule(NewLiteralRule("ingested-ioc", "IP IOC from threat intelligence", "T1102.002", sev, ip, false))
	}
	for _, raw := range reURL.FindAllString(line, -1) {
		indicator := CleanIndicator(raw)
		sev := model.SeverityMedium
		if strongRisk {
			sev = model.SeverityHigh
		}
		c.AddRule(NewLiteralRule("ingested-ioc", "URL IOC from threat intelligence", "T1102.002", sev, indicator, true))
	}
	if strongRisk {
		for _, domain := range reDomain.FindAllString(strings.ToLower(line), -1) {
			domain = CleanIndicator(domain)
			c.AddRule(NewLiteralRule("ingested-ioc", "Domain IOC from threat intelligence", "T1102.002", model.SeverityHigh, domain, false))
		}
	}
}

// AddGitHubActionRules emits workflow-focused indicators from a source line.
func AddGitHubActionRules(c *GeneratedRuleCollector, line string, risky bool) {
	for _, action := range reAction.FindAllString(line, -1) {
		sev := model.SeverityMedium
		if risky {
			sev = model.SeverityHigh
		}
		c.AddRule(NewLiteralRule("github-actions", "Action reference from threat intelligence", "T1195.002", sev, action, true))
	}
}

// AddPyPIRules emits Python package/version indicators from source text.
func AddPyPIRules(c *GeneratedRuleCollector, line string, lower string, risky bool) {
	if !risky && !strings.Contains(lower, "pip") && !strings.Contains(lower, "pypi") && !strings.Contains(lower, "requirements") {
		return
	}
	matches := rePyReq.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		pkg := match[1]
		version := match[3]
		if !IsLikelyPackageName(pkg) {
			continue
		}
		sev := model.SeverityHigh
		if risky {
			sev = model.SeverityCritical
		}
		pattern := fmt.Sprintf(`(?i)\b%s\b\s*(==|===|~=|>=|<=|>|<)\s*%s\b`, regexp.QuoteMeta(pkg), regexp.QuoteMeta(version))
		c.AddRule(model.Rule{
			Title:       fmt.Sprintf("Potentially compromised PyPI package %s %s", pkg, version),
			Description: "Auto-generated package version detector from threat intelligence source.",
			Category:    "pypi-ingested",
			Mitre:       "T1195.002",
			Severity:    sev,
			Pattern:     pattern,
			Target:      model.TargetContent,
		})
	}
	textMatches := rePyText.FindAllStringSubmatch(line, -1)
	for _, match := range textMatches {
		if len(match) < 3 {
			continue
		}
		pkg := match[1]
		version := match[2]
		if !IsLikelyPackageName(pkg) {
			continue
		}
		sev := model.SeverityHigh
		if risky {
			sev = model.SeverityCritical
		}
		pattern := fmt.Sprintf(`(?i)\b%s\b\s*(==|===|~=|>=|<=|>|<)?\s*%s\b`, regexp.QuoteMeta(pkg), regexp.QuoteMeta(version))
		c.AddRule(model.Rule{
			Title:       fmt.Sprintf("Potentially compromised PyPI package %s %s", pkg, version),
			Description: "Auto-generated package version detector from threat intelligence source.",
			Category:    "pypi-ingested",
			Mitre:       "T1195.002",
			Severity:    sev,
			Pattern:     pattern,
			Target:      model.TargetContent,
		})
	}
}

// AddNpmRules emits npm package/version indicators from source text.
func AddNpmRules(c *GeneratedRuleCollector, line string, lower string, risky bool) {
	if !risky && !strings.Contains(lower, "npm") && !strings.Contains(lower, "package-lock") && !strings.Contains(lower, "node_modules") {
		return
	}
	for _, pkg := range reNpmPkg.FindAllString(line, -1) {
		sev := model.SeverityMedium
		if risky {
			sev = model.SeverityHigh
		}
		c.AddRule(NewLiteralRule("npm-ingested", "Potentially risky npm package from threat intelligence", "T1195.002", sev, pkg, true))
	}
}

// AddGoRules emits Go module exposure indicators from source text.
func AddGoRules(c *GeneratedRuleCollector, line string, lower string, risky bool) {
	if !risky && !strings.Contains(lower, "go.mod") && !strings.Contains(lower, "module") {
		return
	}
	matches := reGoMod.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		mod := match[1]
		ver := match[2]
		sev := model.SeverityMedium
		if risky {
			sev = model.SeverityHigh
		}
		c.AddRule(model.Rule{
			Title:       fmt.Sprintf("Potentially risky Go module %s %s", mod, ver),
			Description: "Auto-generated Go module version detector from threat intelligence source.",
			Category:    "go-ingested",
			Mitre:       "T1195.002",
			Severity:    sev,
			Pattern:     fmt.Sprintf(`\b%s\s+%s\b`, regexp.QuoteMeta(mod), regexp.QuoteMeta(ver)),
			Target:      model.TargetContent,
		})
	}
}

// AddCargoRules emits Rust crate exposure indicators from source text.
func AddCargoRules(c *GeneratedRuleCollector, line string, lower string, risky bool) {
	if !risky && !strings.Contains(lower, "cargo") && !strings.Contains(lower, "crates.io") {
		return
	}
	matches := reCargo.FindAllStringSubmatch(line, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		crate := match[1]
		ver := match[2]
		sev := model.SeverityMedium
		if risky {
			sev = model.SeverityHigh
		}
		c.AddRule(model.Rule{
			Title:       fmt.Sprintf("Potentially risky crate %s %s", crate, ver),
			Description: "Auto-generated crate version detector from threat intelligence source.",
			Category:    "cargo-ingested",
			Mitre:       "T1195.002",
			Severity:    sev,
			Pattern:     fmt.Sprintf(`(?i)\b%s\b\s*=\s*"%s"`, regexp.QuoteMeta(crate), regexp.QuoteMeta(ver)),
			Target:      model.TargetContent,
		})
	}
}

// AddContainerRules emits container image and Dockerfile-style indicators from source text.
func AddContainerRules(c *GeneratedRuleCollector, line string, lower string, risky bool) {
	if !risky && !strings.Contains(lower, "docker") && !strings.Contains(lower, "image") && !strings.Contains(lower, "container") {
		return
	}
	for _, image := range reImage.FindAllString(line, -1) {
		sev := model.SeverityMedium
		if risky {
			sev = model.SeverityHigh
		}
		c.AddRule(NewLiteralRule("container-ingested", "Potentially risky container image tag from threat intelligence", "T1195.002", sev, image, true))
	}
}

// AddMcpRules emits MCP poisoning and metadata abuse indicators from source text.
func AddMcpRules(c *GeneratedRuleCollector, line string, lower string, risky bool) {
	if !risky && !strings.Contains(lower, "mcp") && !strings.Contains(lower, "tool poisoning") && !strings.Contains(lower, "resource_metadata") &&
		!strings.Contains(lower, "typosquat") && !strings.Contains(lower, "homoglyph") && !strings.Contains(lower, "lookalike") {
		return
	}
	if strings.Contains(lower, "resource_metadata") || strings.Contains(lower, "authorization_servers") ||
		strings.Contains(lower, "token_endpoint") || strings.Contains(lower, "redirect_uri") {
		c.AddRule(model.Rule{
			Title:       "MCP metadata field from threat intelligence",
			Description: "Auto-generated detector for MCP/OAuth metadata fields requiring strict SSRF and redirect validation.",
			Category:    "mcp-ingested",
			Mitre:       "T1190",
			Severity:    model.SeverityMedium,
			Pattern:     `(?i)(resource_metadata|authorization_servers|token_endpoint|authorization_endpoint|redirect_uri)`,
			Target:      model.TargetContent,
		})
	}
	if strings.Contains(lower, "tool poisoning") || strings.Contains(lower, "shadowing") || strings.Contains(lower, "rug pull") {
		c.AddRule(model.Rule{
			Title:       "MCP poisoning threat marker",
			Description: "Auto-generated detector for MCP tool poisoning/shadowing/rug-pull markers.",
			Category:    "mcp-ingested",
			Mitre:       "T1195.002",
			Severity:    model.SeverityHigh,
			Pattern:     `(?i)(tool poisoning|shadowing|rug pull|cross-server escalation|hidden instructions?)`,
			Target:      model.TargetContent,
		})
	}
	if strings.Contains(lower, "typosquat") || strings.Contains(lower, "homoglyph") || strings.Contains(lower, "lookalike") {
		c.AddRule(model.Rule{
			Title:       "MCP typosquatting or lookalike marker",
			Description: "Auto-generated detector for MCP typosquatting/homoglyph/lookalike risk terms.",
			Category:    "mcp-ingested",
			Mitre:       "T1583",
			Severity:    model.SeverityHigh,
			Pattern:     `(?i)(typosquat|typosquatting|homoglyph|lookalike).{0,80}(mcp|server|tool)`,
			Target:      model.TargetContent,
		})
	}
}

// AddAgentSkillRules emits agent-skill poisoning and instruction abuse indicators from source text.
func AddAgentSkillRules(c *GeneratedRuleCollector, line string, lower string, risky bool) {
	if !risky && !strings.Contains(lower, "skill") && !strings.Contains(lower, "clawhub") &&
		!strings.Contains(lower, "false positive") && !strings.Contains(lower, "flipattack") &&
		!strings.Contains(lower, "scots gaelic") && !strings.Contains(lower, "zulu") {
		return
	}
	if strings.Contains(lower, "clawhub") {
		c.AddRule(model.Rule{
			Title:       "Agent skill registry IOC marker",
			Description: "Auto-generated detector for ClawHub skill IOC references from threat intelligence.",
			Category:    "skills-ingested",
			Mitre:       "T1195.002",
			Severity:    model.SeverityHigh,
			Pattern:     `(?i)\bclawhub\.ai/[a-z0-9._-]+/[a-z0-9._-]+\b`,
			Target:      model.TargetContent,
		})
	}
	if strings.Contains(lower, "ignore previous instructions") || strings.Contains(lower, "do not mention") {
		c.AddRule(model.Rule{
			Title:       "Skill prompt-injection marker",
			Description: "Auto-generated detector for prompt-injection phrasing in skill threat intelligence.",
			Category:    "skills-ingested",
			Mitre:       "T1204.002",
			Severity:    model.SeverityHigh,
			Pattern:     `(?i)(ignore (all|any )?(previous|prior) instructions|do not mention (this|to the user)|without telling the user)`,
			Target:      model.TargetContent,
		})
	}
	if strings.Contains(lower, "false positive") || strings.Contains(lower, "benign") {
		c.AddRule(model.Rule{
			Title:       "Scanner suppression manipulation marker",
			Description: "Auto-generated detector for malicious content attempting to coerce false-positive or benign classification.",
			Category:    "skills-ingested",
			Mitre:       "T1565",
			Severity:    model.SeverityHigh,
			Pattern:     `(?i)(classify.{0,60}(as )?benign|mark.{0,60}false positive|suppress.{0,60}alert|do not alert)`,
			Target:      model.TargetContent,
		})
	}
	if strings.Contains(lower, "flipattack") || strings.Contains(lower, "scots gaelic") || strings.Contains(lower, "zulu") {
		c.AddRule(model.Rule{
			Title:       "Language/encoding prompt-evasion marker",
			Description: "Auto-generated detector for multilingual or encoding-driven prompt evasion tactics.",
			Category:    "skills-ingested",
			Mitre:       "T1027",
			Severity:    model.SeverityMedium,
			Pattern:     `(?i)(flipattack|scots gaelic|zulu|unicode reorder|homoglyph|morse-like encoding)`,
			Target:      model.TargetContent,
		})
	}
}

// AffectedPackageRow represents a single row from a package exposure dataset CSV.
type AffectedPackageRow struct {
	Package           string
	LiteLLMConstraint string
}

// ParseAffectedPackagesCSV reads package exposure datasets into structured rows.
func ParseAffectedPackagesCSV(content string) ([]AffectedPackageRow, bool) {
	reader := csv.NewReader(strings.NewReader(content))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil || len(header) == 0 {
		return nil, false
	}
	if strings.ToLower(strings.TrimSpace(header[0])) != "package" {
		return nil, false
	}

	rows := make([]AffectedPackageRow, 0, 512)
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record) == 0 {
			continue
		}
		pkg := strings.ToLower(strings.TrimSpace(record[0]))
		if !IsLikelyPackageName(pkg) {
			continue
		}
		constraint := ""
		if len(record) > 2 {
			constraint = strings.TrimSpace(record[2])
		}
		rows = append(rows, AffectedPackageRow{
			Package:           pkg,
			LiteLLMConstraint: constraint,
		})
	}
	return rows, len(rows) > 0
}

// AddAffectedPackageExposureRules emits dependency exposure rules from parsed CSV package rows.
func AddAffectedPackageExposureRules(c *GeneratedRuleCollector, rows []AffectedPackageRow) {
	for _, row := range rows {
		pkg := strings.TrimSpace(strings.ToLower(row.Package))
		if pkg == "" {
			continue
		}
		sev := model.SeverityMedium
		if strings.Contains(row.LiteLLMConstraint, "1.82.7") || strings.Contains(row.LiteLLMConstraint, "1.82.8") {
			sev = model.SeverityHigh
		}
		description := "Auto-generated package exposure detector from affected dependency dataset."
		if strings.TrimSpace(row.LiteLLMConstraint) != "" {
			description = fmt.Sprintf(
				"Package appears in affected dependency blast-radius dataset (litellm constraint: %s).",
				row.LiteLLMConstraint,
			)
		}
		c.AddRule(model.Rule{
			Title:       fmt.Sprintf("Affected dependency candidate: %s", pkg),
			Description: description,
			Category:    "dependency-exposure",
			Mitre:       "T1195.002",
			Severity:    sev,
			Pattern:     fmt.Sprintf(`(?i)\b%s\b`, regexp.QuoteMeta(pkg)),
			Target:      model.TargetContent,
		})
	}
}

// NewLiteralRule wraps literal values into safe regex patterns.
func NewLiteralRule(category, title, mitre string, severity model.Severity, value string, caseInsensitive bool) model.Rule {
	value = CleanIndicator(value)
	if value == "" {
		return model.Rule{}
	}
	pattern := regexp.QuoteMeta(value)
	if caseInsensitive {
		pattern = "(?i)" + pattern
	}
	return model.Rule{
		Title:       title,
		Description: "Auto-generated literal indicator from threat intelligence ingestion source.",
		Category:    category,
		Mitre:       mitre,
		Severity:    severity,
		Pattern:     pattern,
		Target:      model.TargetContent,
	}
}

// CleanIndicator normalizes threat-intel indicators for stable matching.
func CleanIndicator(raw string) string {
	cleaned := strings.TrimSpace(raw)
	cleaned = strings.Trim(cleaned, "[](){}<>\"'`.,;")
	cleaned = strings.ReplaceAll(cleaned, "[.]", ".")
	return cleaned
}

// StripMarkup removes basic HTML tags and entity noise from source text.
func StripMarkup(line string) string {
	plain := reHTMLTag.ReplaceAllString(line, " ")
	plain = strings.ReplaceAll(plain, "&mdash;", " ")
	plain = strings.ReplaceAll(plain, "&bull;", " ")
	plain = strings.ReplaceAll(plain, "&nbsp;", " ")
	plain = strings.ReplaceAll(plain, "&rarr;", " ")
	plain = strings.ReplaceAll(plain, "&#39;", "'")
	plain = strings.ReplaceAll(plain, "&amp;", "&")
	plain = strings.Join(strings.Fields(plain), " ")
	return strings.TrimSpace(plain)
}

// IsLikelyPackageName applies conservative package token heuristics.
func IsLikelyPackageName(pkg string) bool {
	lower := strings.ToLower(strings.TrimSpace(pkg))
	if len(lower) < 3 {
		return false
	}
	switch lower {
	case "strong", "span", "div", "code", "table", "packages", "package", "version", "what", "this", "that", "from",
		"only", "just", "confirmed", "malicious", "critical", "high", "medium", "low":
		return false
	}
	// Keep simple names, but reject obviously numeric-only strings.
	allDigits := true
	for _, ch := range lower {
		if ch < '0' || ch > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}

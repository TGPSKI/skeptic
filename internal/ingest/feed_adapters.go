package ingest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// DetectFeedFormat returns "stix", "sigma", "yara", or "" based on the explicit format flag or content heuristics.
func DetectFeedFormat(explicit string, content string) string {
	explicit = strings.ToLower(strings.TrimSpace(explicit))
	if explicit != "" && explicit != "auto" {
		return explicit
	}
	trimmed := strings.TrimSpace(content)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		if strings.Contains(trimmed[:min(len(trimmed), 512)], `"type"`) &&
			(strings.Contains(trimmed[:min(len(trimmed), 512)], `"bundle"`) ||
				strings.Contains(trimmed[:min(len(trimmed), 512)], `"indicator"`)) {
			return "stix"
		}
	}
	if strings.HasPrefix(trimmed, "title:") ||
		(strings.Contains(trimmed[:min(len(trimmed), 512)], "detection:") &&
			strings.Contains(trimmed[:min(len(trimmed), 512)], "logsource:")) {
		return "sigma"
	}
	if strings.HasPrefix(trimmed, "rule ") || strings.Contains(trimmed[:min(len(trimmed), 512)], "\nrule ") {
		return "yara"
	}
	return ""
}

// ParseSTIXBundle extracts indicators from a STIX 2.1 JSON bundle.
func ParseSTIXBundle(data []byte) ([]model.Rule, error) {
	var bundle struct {
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("stix: unmarshal: %w", err)
	}
	var rules []model.Rule
	for _, raw := range bundle.Objects {
		var obj struct {
			Type    string `json:"type"`
			Name    string `json:"name"`
			Pattern string `json:"pattern"`
		}
		if json.Unmarshal(raw, &obj) != nil {
			continue
		}
		if obj.Type != "indicator" || strings.TrimSpace(obj.Pattern) == "" {
			continue
		}
		// STIX patterns use [type:field = 'value'] syntax; extract the value for regex use
		extracted := ExtractSTIXPatternValue(obj.Pattern)
		if extracted == "" {
			continue
		}
		rules = append(rules, model.Rule{
			ID:          fmt.Sprintf("STIX-%04d", len(rules)+1),
			Title:       obj.Name,
			Description: fmt.Sprintf("STIX indicator: %s", obj.Name),
			Category:    "threat-intel-stix",
			Mitre:       "T1595",
			Severity:    model.SeverityHigh,
			Pattern:     regexp.QuoteMeta(extracted),
			Target:      model.TargetContent,
		})
	}
	return rules, nil
}

// ExtractSTIXPatternValue pulls the value from a STIX pattern expression.
func ExtractSTIXPatternValue(pattern string) string {
	// Try "= '" (with space) first, then "='" (no space)
	idx := strings.Index(pattern, "= '")
	start := idx + 3
	if idx < 0 {
		idx = strings.Index(pattern, "='")
		start = idx + 2
	}
	if idx < 0 {
		return ""
	}
	end := strings.Index(pattern[start:], "'")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(pattern[start : start+end])
}

// ParseSigmaRule extracts detection patterns from a Sigma rule YAML.
func ParseSigmaRule(data []byte) []model.Rule {
	var rules []model.Rule
	content := string(data)
	lines := strings.Split(content, "\n")

	var title, ruleID string
	var inDetection bool
	var patterns []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "title:") {
			title = strings.TrimSpace(strings.TrimPrefix(trimmed, "title:"))
		}
		if strings.HasPrefix(trimmed, "id:") {
			ruleID = strings.TrimSpace(strings.TrimPrefix(trimmed, "id:"))
		}
		if strings.HasPrefix(trimmed, "detection:") {
			inDetection = true
			continue
		}
		if inDetection && (strings.HasPrefix(trimmed, "level:") || strings.HasPrefix(trimmed, "logsource:")) {
			inDetection = false
		}
		if inDetection && strings.Contains(trimmed, ":") {
			parts := strings.SplitN(trimmed, ":", 2)
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, "'\"")
			if len(val) >= 4 {
				patterns = append(patterns, val)
			}
		}
	}
	if ruleID == "" {
		ruleID = "SIGMA"
	}
	for i, pat := range patterns {
		sigmaPattern := pat
		if strings.Contains(sigmaPattern, "*") {
			sigmaPattern = strings.ReplaceAll(sigmaPattern, "*", ".*")
		}
		if len(sigmaPattern) > 500 {
			continue
		}
		if _, err := regexp.Compile(sigmaPattern); err != nil {
			continue
		}
		rules = append(rules, model.Rule{
			ID:          fmt.Sprintf("SIGMA-%s-%03d", ruleID[:min(len(ruleID), 8)], i+1),
			Title:       title,
			Description: fmt.Sprintf("Sigma detection: %s", title),
			Category:    "threat-intel-sigma",
			Mitre:       "T1059",
			Severity:    model.SeverityMedium,
			Pattern:     sigmaPattern,
			Target:      model.TargetContent,
		})
	}
	return rules
}

var (
	reYARARule   = regexp.MustCompile(`^rule\s+(\w+)`)
	reYARAString = regexp.MustCompile(`^\s*\$\w+\s*=\s*"([^"]+)"`)
)

// ParseYARAStrings extracts string patterns from YARA rules for content scanning.
func ParseYARAStrings(data []byte) []model.Rule {
	var rules []model.Rule
	content := string(data)
	lines := strings.Split(content, "\n")

	var currentRule string
	var inStrings bool

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if matches := reYARARule.FindStringSubmatch(trimmed); len(matches) > 1 {
			currentRule = matches[1]
			inStrings = false
		}
		if trimmed == "strings:" {
			inStrings = true
			continue
		}
		if trimmed == "condition:" {
			inStrings = false
			continue
		}
		if inStrings {
			if matches := reYARAString.FindStringSubmatch(line); len(matches) > 1 {
				str := matches[1]
				if len(str) < 4 {
					continue
				}
				rules = append(rules, model.Rule{
					ID:          fmt.Sprintf("YARA-%s-%03d", currentRule, len(rules)+1),
					Title:       fmt.Sprintf("YARA string from %s", currentRule),
					Description: fmt.Sprintf("String pattern extracted from YARA rule %s.", currentRule),
					Category:    "threat-intel-yara",
					Mitre:       "T1027",
					Severity:    model.SeverityMedium,
					Pattern:     regexp.QuoteMeta(str),
					Target:      model.TargetContent,
				})
			}
		}
	}
	return rules
}

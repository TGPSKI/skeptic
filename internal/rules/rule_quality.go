package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

// RuleQualityIssue records a single analyst-facing quality problem for a rule spec.
type RuleQualityIssue struct {
	RuleID  string
	Message string
}

var (
	reRuleIDFormat = regexp.MustCompile(`^[A-Z0-9][A-Z0-9._-]{2,}$`)
	reMitreFormat  = regexp.MustCompile(`^(T\d{4}(?:\.\d{3})?|TA\d{4})$`)
)

// ParseRuleQualityMode validates enforcement behavior for externally loaded/generated rules.
func ParseRuleQualityMode(raw string) (model.RuleQualityMode, error) {
	mode := model.RuleQualityMode(strings.ToLower(strings.TrimSpace(raw)))
	switch mode {
	case model.RuleQualityOff, model.RuleQualityWarn, model.RuleQualityStrict:
		return mode, nil
	default:
		return "", fmt.Errorf("expected one of off|warn|strict, got %q", raw)
	}
}

// ValidateRuleSpecQuality returns analyst-facing quality issues for one rule specification.
func ValidateRuleSpecQuality(spec model.RuleSpec) []RuleQualityIssue {
	issues := make([]RuleQualityIssue, 0, 8)
	ruleID := strings.TrimSpace(spec.ID)

	if !reRuleIDFormat.MatchString(ruleID) {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "rule id should use stable uppercase token format (example: TEAM-IOC-001)",
		})
	}
	if len(strings.TrimSpace(spec.Title)) < 8 {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "title is too short; provide a precise detection name",
		})
	}
	if len(strings.TrimSpace(spec.Description)) < 16 {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "description is too short; include analyst-facing context",
		})
	}
	if spec.Target != model.TargetContent && spec.Target != model.TargetPath {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "target should be content or path",
		})
	}

	pattern := strings.TrimSpace(spec.Pattern)
	if len(pattern) < 4 {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "pattern is too short and likely noisy",
		})
	}
	if len(pattern) > 2048 {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "pattern is excessively long and difficult to maintain",
		})
	}

	patternLower := strings.ToLower(pattern)
	if patternLower == ".*" || patternLower == "(?i).*" || patternLower == ".+" || patternLower == "(?i).+" {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "pattern is over-broad and will match nearly everything",
		})
	}
	if strings.Count(pattern, ".*") > 4 {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "pattern contains many wildcard spans and may be high-noise",
		})
	}
	if strings.Contains(pattern, "(.*)+") || strings.Contains(pattern, "(.+)+") || strings.Contains(pattern, "(?:.*){") {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "pattern contains nested broad quantifiers; tighten for maintainability",
		})
	}

	if mitre := strings.TrimSpace(spec.Mitre); mitre != "" && !reMitreFormat.MatchString(mitre) {
		issues = append(issues, RuleQualityIssue{
			RuleID:  ruleID,
			Message: "mitre field should be ATT&CK technique/tactic id (Txxxx, Txxxx.xxx, or TAxxxx)",
		})
	}

	return issues
}

// EnforceRuleQualityForSpecs applies warn/strict behavior to a full rule set.
func EnforceRuleQualityForSpecs(specs []model.RuleSpec, source string, mode model.RuleQualityMode, logger *logging.Logger) error {
	if mode == model.RuleQualityOff {
		return nil
	}

	issues := make([]RuleQualityIssue, 0, len(specs))
	for _, spec := range specs {
		issues = append(issues, ValidateRuleSpecQuality(spec)...)
	}
	if len(issues) == 0 {
		return nil
	}

	for _, issue := range issues {
		msg := fmt.Sprintf("rule quality (%s): %s", source, issue.Message)
		if strings.TrimSpace(issue.RuleID) != "" {
			msg = fmt.Sprintf("rule quality (%s, %s): %s", source, issue.RuleID, issue.Message)
		}
		if logger != nil {
			logger.Warnf("%s", msg)
		}
	}
	if mode == model.RuleQualityStrict {
		return fmt.Errorf("rule quality check failed for %s with %d issue(s)", source, len(issues))
	}
	return nil
}

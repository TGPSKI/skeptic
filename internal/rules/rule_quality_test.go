package rules

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
)

func TestParseRuleQualityMode(t *testing.T) {
	for _, raw := range []string{"off", "warn", "strict", " WARN "} {
		if _, err := ParseRuleQualityMode(raw); err != nil {
			t.Fatalf("ParseRuleQualityMode(%q) failed: %v", raw, err)
		}
	}
	if _, err := ParseRuleQualityMode("nope"); err == nil {
		t.Fatalf("expected invalid mode to fail")
	}
}

func TestValidateRuleSpecQuality(t *testing.T) {
	spec := model.RuleSpec{
		ID:          "bad",
		Title:       "short",
		Description: "tiny",
		Category:    "x",
		Mitre:       "INVALID",
		Severity:    model.SeverityHigh,
		Pattern:     ".*",
		Target:      model.RuleTarget("other"),
	}
	issues := ValidateRuleSpecQuality(spec)
	if len(issues) == 0 {
		t.Fatalf("expected quality issues for intentionally weak rule")
	}
}

func TestEnforceRuleQualityForSpecsWarnAndStrict(t *testing.T) {
	bad := []model.RuleSpec{
		{
			ID:          "BAD",
			Title:       "bad",
			Description: "bad",
			Category:    "x",
			Mitre:       "T1234",
			Severity:    model.SeverityHigh,
			Pattern:     ".*",
			Target:      model.TargetContent,
		},
	}

	var logBuf bytes.Buffer
	logger := logging.NewLogger(logging.LogWarn, &logBuf)
	if err := EnforceRuleQualityForSpecs(bad, "test-source", model.RuleQualityWarn, logger); err != nil {
		t.Fatalf("warn mode should not return error: %v", err)
	}
	if !strings.Contains(logBuf.String(), "rule quality") {
		t.Fatalf("expected quality warnings in logger output")
	}

	if err := EnforceRuleQualityForSpecs(bad, "test-source", model.RuleQualityStrict, logger); err == nil {
		t.Fatalf("strict mode should return error")
	}
}

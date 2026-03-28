package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func FuzzLoadRulesFromFile(f *testing.F) {
	validPack, _ := json.Marshal(model.RulePack{
		Version: 1,
		Name:    "test",
		Rules: []model.RuleSpec{{
			ID: "TEST-001", Pattern: "test", Severity: model.SeverityHigh, Target: model.TargetContent,
		}},
	})
	validBare, _ := json.Marshal([]model.RuleSpec{{
		ID: "BARE-001", Pattern: "bare", Severity: model.SeverityLow, Target: model.TargetContent,
	}})
	f.Add(validPack)
	f.Add(validBare)
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "rules.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Skip("write error:", err)
		}
		// LoadRulesFromFile may return rules or an error; neither should panic.
		_, _ = LoadRulesFromFile(path)
	})
}

func FuzzCompileRuleSpecs(f *testing.F) {
	f.Add("TEST-001", "simple-pattern", "high", "content")
	f.Add("TEST-002", `(?i)\bmalicious\b`, "critical", "path")
	f.Add("", "", "", "")
	f.Add("BAD", `(unclosed`, "medium", "content")

	f.Fuzz(func(t *testing.T, id, pattern, severity, target string) {
		specs := []model.RuleSpec{{
			ID:       id,
			Pattern:  pattern,
			Severity: model.Severity(severity),
			Target:   model.RuleTarget(target),
		}}
		// CompileRuleSpecs may return rules or an error; neither should panic.
		_, _ = CompileRuleSpecs(specs, "fuzz-input")
	})
}

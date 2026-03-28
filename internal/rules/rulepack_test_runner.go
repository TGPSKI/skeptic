package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// CollectTestFiles walks a directory tree and returns paths to all rules.test.*.json files.
func CollectTestFiles(rulesDir string) ([]string, error) {
	absDir, err := filepath.Abs(model.ExpandHomePath(rulesDir))
	if err != nil {
		return nil, err
	}
	var out []string
	err = filepath.WalkDir(absDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.Contains(name, ".test.") && strings.HasSuffix(name, ".json") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// RulePackTestResult holds the outcome of running a single test pack.
type RulePackTestResult struct {
	TestFile string
	Passed   int
	Failed   int
	Skipped  int
	Errors   []string
}

// RunRulePackTests loads a test pack JSON, resolves the companion rules file,
// compiles the rules, and runs each test case's should_match / should_not_match
// assertions against the compiled regex patterns.
func RunRulePackTests(testFilePath string) (*RulePackTestResult, error) {
	data, err := os.ReadFile(testFilePath)
	if err != nil {
		return nil, fmt.Errorf("read test file: %w", err)
	}
	var tp model.RuleTestPack
	if err := json.Unmarshal(data, &tp); err != nil {
		return nil, fmt.Errorf("parse test file: %w", err)
	}
	if tp.Version != 1 {
		return nil, fmt.Errorf("unsupported test pack version: %d", tp.Version)
	}

	rulesPath := filepath.Join(filepath.Dir(testFilePath), tp.RulesFile)
	rules, err := LoadRulesFromFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("load rules file %s: %w", tp.RulesFile, err)
	}

	ruleByID := make(map[string]Rule, len(rules))
	for _, r := range rules {
		ruleByID[r.ID] = r
	}

	result := &RulePackTestResult{TestFile: testFilePath}

	for _, tc := range tp.Tests {
		rule, ok := ruleByID[tc.RuleID]
		if !ok {
			result.Skipped++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: rule not found in %s", tc.RuleID, tp.RulesFile))
			continue
		}

		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s: pattern compile error: %v", tc.RuleID, err))
			continue
		}

		for _, input := range tc.ShouldMatch {
			if re.MatchString(input) {
				result.Passed++
			} else {
				result.Failed++
				result.Errors = append(result.Errors, fmt.Sprintf("%s: should_match failed: %q", tc.RuleID, truncate(input, 80)))
			}
		}
		for _, input := range tc.ShouldNotMatch {
			if re.MatchString(input) {
				result.Failed++
				result.Errors = append(result.Errors, fmt.Sprintf("%s: should_not_match failed: %q", tc.RuleID, truncate(input, 80)))
			} else {
				result.Passed++
			}
		}
	}

	return result, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

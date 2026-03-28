package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TGPSKI/skeptic/internal/rules"
)

func TestRulePackCorpus(t *testing.T) {
	rulesDir := filepath.Join(repoRoot(t), "rulepacks", "campaigns")
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Skip("rulepacks/campaigns/ not found")
	}

	testFiles, err := rules.CollectTestFiles(rulesDir)
	if err != nil {
		t.Fatalf("collect test files: %v", err)
	}
	if len(testFiles) == 0 {
		t.Skip("no rules.test.*.json files found")
	}

	for _, tf := range testFiles {
		rel, _ := filepath.Rel(rulesDir, tf)
		t.Run(rel, func(t *testing.T) {
			result, err := rules.RunRulePackTests(tf)
			if err != nil {
				t.Fatalf("run test pack: %v", err)
			}
			for _, e := range result.Errors {
				t.Error(e)
			}
			t.Logf("passed=%d failed=%d skipped=%d", result.Passed, result.Failed, result.Skipped)
			if result.Failed > 0 {
				t.Fail()
			}
		})
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod)")
		}
		dir = parent
	}
}

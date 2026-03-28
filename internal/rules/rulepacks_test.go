package rules

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
)

func TestBuildRuleHashMap(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "rules.json")
	if err := os.WriteFile(path, []byte("[]"), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	hashes, err := BuildRuleHashMap(path, strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("BuildRuleHashMap failed: %v", err)
	}
	abs, _ := filepath.Abs(path)
	if hashes[abs] != strings.Repeat("a", 64) {
		t.Fatalf("unexpected hash map entry: %+v", hashes)
	}

	if _, err := BuildRuleHashMap(path, "abc"); err == nil {
		t.Fatalf("expected invalid hash to fail")
	}
}

func TestCollectRuleFiles(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.json")
	b := filepath.Join(root, "b.json")
	c := filepath.Join(root, "note.txt")
	for _, p := range []string{a, b, c} {
		if err := os.WriteFile(p, []byte("[]"), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", p, err)
		}
	}

	got, err := CollectRuleFiles(a+","+a, root)
	if err != nil {
		t.Fatalf("CollectRuleFiles failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rule files (.json + explicit), got %d: %v", len(got), got)
	}
	if filepath.Ext(got[0]) != ".json" || filepath.Ext(got[1]) != ".json" {
		t.Fatalf("expected only json files: %v", got)
	}
}

func TestLoadRulesFromFileAndCompileRuleSpecs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "pack.json")
	content := `{"version":1,"name":"x","generated_at":"2026-01-01T00:00:00Z","rules":[{"id":"R1","title":"x","description":"desc ok","category":"cat","mitre":"T1059","severity":"high","pattern":"(?i)evil","target":"content"}]}`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}

	rules, err := LoadRulesFromFile(path)
	if err != nil {
		t.Fatalf("LoadRulesFromFile failed: %v", err)
	}
	if len(rules) != 1 || rules[0].RE == nil {
		t.Fatalf("expected compiled rule, got %+v", rules)
	}

	_, err = CompileRuleSpecs([]model.RuleSpec{{
		ID:       "R2",
		Severity: model.SeverityHigh,
		Pattern:  "(",
		Target:   model.TargetContent,
	}}, "test")
	if err == nil {
		t.Fatalf("expected invalid regex to fail CompileRuleSpecs")
	}
}

func TestDedupeRules(t *testing.T) {
	r := model.Rule{
		ID:       "R",
		Severity: model.SeverityHigh,
		Pattern:  "x",
		Target:   model.TargetContent,
		RE:       regexp.MustCompile("x"),
	}
	out := DedupeRules([]model.Rule{r, r})
	if len(out) != 1 {
		t.Fatalf("expected deduped rules length 1, got %d", len(out))
	}
}

func TestBuildRuleSetRequireSignedRulesValidation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "rules.json")
	content := `[
  {"id":"R3","title":"x","description":"description long enough","category":"cat","mitre":"T1059","severity":"high","pattern":"(?i)evil","target":"content"}
]`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	if _, err := BuildRuleSet(false, nil, path, "", "", "", true, model.RuleQualityWarn, nil); err == nil {
		t.Fatalf("expected require-signed-rules without pubkey to fail")
	}
}

func TestBuildRuleSetWithExternalRulePack(t *testing.T) {
	root := t.TempDir()
	rulePackPath := filepath.Join(root, "rules.json")
	err := os.WriteFile(rulePackPath, []byte(`{
  "version": 1,
  "name": "test-pack",
  "generated_at": "2026-03-27T00:00:00Z",
  "rules": [
    {
      "id": "EXT-001",
      "title": "External IOC",
      "description": "external rule test",
      "category": "external",
      "mitre": "T1102.002",
      "severity": "high",
      "pattern": "(?i)evil\\.example",
      "target": "content"
    }
  ]
}`), 0o644)
	if err != nil {
		t.Fatalf("write rule pack: %v", err)
	}

	r, err := BuildRuleSet(false, nil, rulePackPath, "", "", "", false, model.RuleQualityWarn, nil)
	if err != nil {
		t.Fatalf("build rule set failed: %v", err)
	}
	if len(r) != 1 {
		t.Fatalf("expected 1 external rule, got %d", len(r))
	}
	if r[0].ID != "EXT-001" {
		t.Fatalf("unexpected rule ID: %s", r[0].ID)
	}

	notePath := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(notePath, []byte("connect to evil.example now"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	report, err := scanpkg.ScanWithOptions(context.Background(), r, model.ScanOptions{
		Paths:                  []string{root},
		Profile:                model.ProfileRepo,
		MaxBytes:               scanpkg.DefaultMaxBytes,
		FailOn:                 model.SeverityHigh,
		IgnorePermissionErrors: false,
		Workers:                2,
		MaxFindings:            200,
		MaxFindingsPerFile:     50,
		ScanStyle:              model.ScanStylePattern,
		ThreatMode:             model.ThreatModeAll,
		PolicyChecks:           false,
		RedactSecrets:          true,
	})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if !report.ThresholdExceeded {
		t.Fatalf("expected external high severity rule to trigger fail threshold")
	}
}

func TestBuildRuleSetRejectsHashMismatch(t *testing.T) {
	root := t.TempDir()
	rulePackPath := filepath.Join(root, "rules.json")
	if err := os.WriteFile(rulePackPath, []byte(`[
  {
    "id": "EXT-HASH-001",
    "title": "hash test",
    "description": "hash test",
    "category": "external",
    "mitre": "T1102.002",
    "severity": "high",
    "pattern": "(?i)evil\\.example",
    "target": "content"
  }
]`), 0o644); err != nil {
		t.Fatalf("write rule pack: %v", err)
	}

	_, err := BuildRuleSet(false, nil, rulePackPath, "", strings.Repeat("a", 64), "", false, model.RuleQualityWarn, nil)
	if err == nil {
		t.Fatalf("expected sha256 mismatch error")
	}
}

func TestBuildRuleSetSignedRulePackVerification(t *testing.T) {
	root := t.TempDir()
	rulePackPath := filepath.Join(root, "signed-rules.json")
	rulePackContent := []byte(`[
  {
    "id": "EXT-SIG-001",
    "title": "signed ioc",
    "description": "signed rule pack test",
    "category": "external",
    "mitre": "T1102.002",
    "severity": "high",
    "pattern": "(?i)evil\\.signed\\.example",
    "target": "content"
  }
]`)
	if err := os.WriteFile(rulePackPath, rulePackContent, 0o644); err != nil {
		t.Fatalf("write rule pack failed: %v", err)
	}

	privateDER, publicDER, err := GenerateRulepackKeypair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	privatePath := filepath.Join(root, "rulepack.key.pem")
	publicPath := filepath.Join(root, "rulepack.pub.pem")
	if err := WritePEMFile(privatePath, "PRIVATE KEY", privateDER, 0o600); err != nil {
		t.Fatalf("write private key failed: %v", err)
	}
	if err := WritePEMFile(publicPath, "PUBLIC KEY", publicDER, 0o644); err != nil {
		t.Fatalf("write public key failed: %v", err)
	}

	signature, err := SignRulepackFile(rulePackPath, privatePath, "test-key")
	if err != nil {
		t.Fatalf("sign rule pack failed: %v", err)
	}
	if err := WriteRulepackSignature(DefaultRulepackSignaturePath(rulePackPath), signature); err != nil {
		t.Fatalf("write signature failed: %v", err)
	}

	r, err := BuildRuleSet(false, nil, rulePackPath, "", "", publicPath, true, model.RuleQualityWarn, nil)
	if err != nil {
		t.Fatalf("signed rule pack should verify, got error: %v", err)
	}
	if len(r) != 1 {
		t.Fatalf("expected 1 loaded rule, got %d", len(r))
	}

	if err := os.WriteFile(rulePackPath, append(rulePackContent, []byte("\n")...), 0o644); err != nil {
		t.Fatalf("tamper write failed: %v", err)
	}
	_, err = BuildRuleSet(false, nil, rulePackPath, "", "", publicPath, true, model.RuleQualityWarn, nil)
	if err == nil {
		t.Fatalf("expected signature verification failure after tampering")
	}
}

func TestBuildRuleSetStrictQualityRejectsBroadPattern(t *testing.T) {
	root := t.TempDir()
	rulePackPath := filepath.Join(root, "bad-rules.json")
	if err := os.WriteFile(rulePackPath, []byte(`[
  {
    "id": "BAD-001",
    "title": "bad",
    "description": "bad",
    "category": "external",
    "mitre": "T1102.002",
    "severity": "high",
    "pattern": ".*",
    "target": "content"
  }
]`), 0o644); err != nil {
		t.Fatalf("write bad rule pack failed: %v", err)
	}

	_, err := BuildRuleSet(false, nil, rulePackPath, "", "", "", false, model.RuleQualityStrict, nil)
	if err == nil {
		t.Fatalf("expected strict rule quality mode to reject over-broad rule")
	}
}

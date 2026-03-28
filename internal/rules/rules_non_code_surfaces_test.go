package rules

import "testing"

func TestNonCodeSurfacesRules(t *testing.T) {
	rules := nonCodeSurfacesRules()
	assertRuleCount(t, "nonCodeSurfacesRules", rules, 28)
	validateRuleSlice(t, "nonCodeSurfacesRules", rules,
		"SCM-GIT-001", "SCM-PKG-001", "AGT-ART-004",
		"CI-DEPBOT-001", "CI-DEPBOT-002", "CI-DEPBOT-003",
		"CI-DEPBOT-004", "CI-DEPBOT-005", "CI-DEPBOT-006", "CI-DEPBOT-007",
		"CI-DEPBOT-008", "CI-DEPBOT-009",
		"SCM-TRUST-005")
}

func TestProof_CI_DEPBOT_001(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-001", []nonCodeProofCase{
		// Renovate config with extends but no age gate
		{`"extends": ["config:base"]`, true},
		{`"extends": [":separateMinorPatchReleases"]`, true},
		// Config with minimumReleaseAge on same line — excluded
		{`"extends": ["config:base"] minimumReleaseAge`, false},
		{`"extends": ["config:base"] stabilityDays`, false},
		// No extends keyword
		{`"automerge": true`, false},
		// Weaponizable: comment containing minimumReleaseAge should suppress
		// This is a known limitation of the line-level engine — test documents it
		{`"extends": ["config:base"] // minimumReleaseAge TBD`, false},
	})
}

func TestProof_CI_DEPBOT_002(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-002", []nonCodeProofCase{
		{`"groupName": "minor-updates"`, true},
		{`"groupName": "all-patch-updates"`, true},
		{`"groupName": "minor-and-patch"`, true},
		{`"groupName": "major-updates"`, false},
		{`"groupName": "dependencies"`, false},
	})
}

func TestProof_CI_DEPBOT_003(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-003", []nonCodeProofCase{
		{`"automerge": true`, true},
		{`"automerge":true`, true},
		{`"automerge": false`, false},
		{`automergeType: "pr"`, false},
	})
}

func TestProof_CI_DEPBOT_004(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-004", []nonCodeProofCase{
		{`"rangeStrategy": "bump"`, true},
		{`"rangeStrategy": "pin"`, false},
		{`"rangeStrategy": "replace"`, false},
	})
}

func TestProof_CI_DEPBOT_005(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-005", []nonCodeProofCase{
		// Single-line match
		{`"automerge": true, "matchFileNames": [".tekton", ".github"]`, true},
		// No automerge
		{`"matchFileNames": [".tekton"]`, false},
	})
}

func TestProof_CI_DEPBOT_006(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-006", []nonCodeProofCase{
		// Extends without vulnerability alerts
		{`"extends": ["config:base"]`, true},
		// Excluded: has vulnerabilityAlerts on same line
		{`"extends": ["config:base"] vulnerabilityAlerts`, false},
		{`"extends": ["config:base"] osvVulnerabilityAlerts`, false},
	})
}

func TestProof_CI_DEPBOT_007(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-007", []nonCodeProofCase{
		// Single-line gomod disable
		{`"matchManagers": ["gomod"], "enabled": false`, true},
		// Not gomod
		{`"matchManagers": ["npm"], "enabled": false`, false},
	})
}

func TestProof_CI_DEPBOT_008(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-008", []nonCodeProofCase{
		{`package-ecosystem: npm`, true},
		{`  package-ecosystem: "npm"`, true},
		// ExcludePattern is evaluated per line (see scan worker): reviewers/assignees must appear on the same line
		{`package-ecosystem: npm  reviewers: security-team`, false},
		{`assignees: [bot]  package-ecosystem: gomod`, false},
		// No package-ecosystem
		{`directory: /`, false},
	})
}

func TestProof_CI_DEPBOT_009(t *testing.T) {
	runNonCodeProof(t, "CI-DEPBOT-009", []nonCodeProofCase{
		{`dependency-type: all`, true},
		{`dependency-type: production`, true},
		{`dependency-type: development`, false},
		{`dependency-type: direct`, false},
	})
}

func TestProof_SCM_TRUST_005(t *testing.T) {
	runNonCodeProof(t, "SCM-TRUST-005", []nonCodeProofCase{
		{`FROM quay.io/jsmith/myimage:latest`, true},
		{`FROM ghcr.io/personaluser/tool:v1`, true},
		{`FROM docker.io/someuser/app:latest`, true},
		// Official images (no personal namespace segment)
		{`FROM alpine:latest`, false},
		{`FROM node:18`, false},
	})
}

func TestProof_SCM_TRUST_005_PathPattern(t *testing.T) {
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}
	rule := byID["SCM-TRUST-005"]
	paths := []struct {
		path string
		want bool
	}{
		{"Dockerfile", true},
		{"build/Dockerfile.prod", true},
		{"Containerfile", true},
		{"src/main.go", false},
	}
	for _, p := range paths {
		got := rule.PathPattern.MatchString(p.path)
		if got != p.want {
			t.Errorf("SCM-TRUST-005 PathPattern on %q: got %v want %v", p.path, got, p.want)
		}
	}
}

type nonCodeProofCase struct {
	input     string
	wantMatch bool
}

func runNonCodeProof(t *testing.T, ruleID string, cases []nonCodeProofCase) {
	t.Helper()
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}
	rule, ok := byID[ruleID]
	if !ok {
		t.Fatalf("missing rule %s in DefaultRules()", ruleID)
	}
	if rule.RE == nil {
		t.Fatalf("rule %s has nil compiled regex", ruleID)
	}
	for _, c := range cases {
		matched := rule.RE.MatchString(c.input)
		excluded := false
		if matched && rule.ExcludePattern != nil {
			excluded = rule.ExcludePattern.MatchString(c.input)
		}
		effective := matched && !excluded
		if c.wantMatch && !effective {
			if excluded {
				t.Errorf("[%s] should match but ExcludePattern suppressed: %q", ruleID, c.input)
			} else {
				t.Errorf("[%s] should match but pattern did not match: %q", ruleID, c.input)
			}
		}
		if !c.wantMatch && effective {
			t.Errorf("[%s] should NOT match but did: %q", ruleID, c.input)
		}
	}
}

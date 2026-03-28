package checks

import (
	"testing"
)

func TestCheckDomainTyposquat(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantRuleID string
		wantNone   bool
	}{
		{
			name:       "edit distance near-miss to aquasecurity.com",
			content:    `curl https://scan.aquasecurtiy.com/payload`,
			wantRuleID: "DOM-TYPO-001",
		},
		{
			name:       "TLD swap github.com to github.org",
			content:    `wget https://github.org/evil/release.tar.gz`,
			wantRuleID: "DOM-TYPO-002",
		},
		{
			name:       "TLD swap pypi.org to pypi.com",
			content:    `https://pypi.com/project/evil-package`,
			wantRuleID: "DOM-TYPO-002",
		},
		{
			name:       "homoglyph 0 for o in docker.com",
			content:    `https://d0cker.com/images/alpine`,
			wantRuleID: "DOM-TYPO-003",
		},
		{
			name:       "homoglyph rn for m in github.com",
			content:    `https://github.corn/evil/repo`,
			wantRuleID: "DOM-TYPO-003",
		},
		{
			name:     "exact match is not a finding",
			content:  `https://github.com/aquasecurity/trivy`,
			wantNone: true,
		},
		{
			name:     "subdomain of known vendor is not a finding",
			content:  `https://api.github.com/repos`,
			wantNone: true,
		},
		{
			name:     "unrelated domain is not a finding",
			content:  `https://example.com/something`,
			wantNone: true,
		},
		{
			name:     "domain too different for edit distance",
			content:  `https://totally-different-domain.com/path`,
			wantNone: true,
		},
		{
			name:       "edit distance near-miss to gitlab.com",
			content:    `https://gitllab.com/org/repo`,
			wantRuleID: "DOM-TYPO-001",
		},
		{
			name:       "edit distance near-miss to pypi.org",
			content:    `https://pypl.org/project/evil`,
			wantRuleID: "DOM-TYPO-001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CheckDomainTyposquat("test.go", tt.content, false)

			if tt.wantNone {
				if len(findings) > 0 {
					t.Fatalf("expected no findings, got %d: %v", len(findings), findings[0].RuleID)
				}
				return
			}

			found := false
			for _, f := range findings {
				if f.RuleID == tt.wantRuleID {
					found = true
					break
				}
			}
			if !found {
				ids := make([]string, len(findings))
				for i, f := range findings {
					ids[i] = f.RuleID
				}
				t.Fatalf("expected finding %s, got %v", tt.wantRuleID, ids)
			}
		})
	}
}

func TestVendorOwnedAltDomains(t *testing.T) {
	noFire := []string{
		`Visit https://user.github.io/docs for more info`,
		`See https://docs.atlassian.net/wiki/spaces`,
		`Available at https://pkg.terraform.io/`,
		`Check https://kubernetes.io/docs/`,
		`Published at https://project.readthedocs.io/en/latest/`,
		`Pull from https://registry.docker.io/v2/library`,
		`Host at https://crates.io/crates/serde`,
		`Track at https://sentry.io/issues/`,
		`Scan at https://snyk.io/vuln/`,
		`CI at https://jenkins.io/doc/`,
		`Search at https://elastic.co/guide/`,
		`Docs at https://google.dev/apis`,
	}
	for _, content := range noFire {
		findings := CheckDomainTyposquat("test.md", content, false)
		for _, f := range findings {
			if f.RuleID == "DOM-TYPO-002" {
				t.Errorf("vendor-owned domain should not fire DOM-TYPO-002: %s -> %s", content, f.Match)
			}
		}
	}

	findings := CheckDomainTyposquat("test.md", `https://github.org/evil/repo`, false)
	found := false
	for _, f := range findings {
		if f.RuleID == "DOM-TYPO-002" {
			found = true
		}
	}
	if !found {
		t.Error("github.org should still fire DOM-TYPO-002 (TLD swap, not a vendor-owned domain)")
	}
}

func TestCheckDomainTyposquatDeduplicates(t *testing.T) {
	content := `
https://aquasecurtiy.com/a
https://aquasecurtiy.com/b
https://aquasecurtiy.com/c
`
	findings := CheckDomainTyposquat("test.go", content, false)
	count := 0
	for _, f := range findings {
		if f.Match == "aquasecurtiy.com" {
			count++
		}
	}
	if count > 1 {
		t.Fatalf("expected deduplication, got %d findings for same domain", count)
	}
}

func TestNormalizeHomoglyphs(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"d0cker", "docker"},
		{"githuh.corn", "githuh.com"},
		{"norrnaltext", "normaltext"},
		{"regular", "regular"},
	}
	for _, tt := range tests {
		got := normalizeHomoglyphs(tt.input)
		if got != tt.want {
			t.Errorf("normalizeHomoglyphs(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

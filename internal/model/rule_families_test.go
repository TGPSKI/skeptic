package model

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRuleFamilyPrefixesAreWellFormed pins the shape of the table so a typo
// cannot silently create a family that never matches anything.
func TestRuleFamilyPrefixesAreWellFormed(t *testing.T) {
	seen := make(map[string]struct{}, len(ruleFamilies))
	for _, fam := range ruleFamilies {
		if fam.Prefix == "" {
			t.Error("rule family with empty prefix")
			continue
		}
		if fam.Prefix != strings.ToUpper(fam.Prefix) {
			t.Errorf("family %q: prefix must be uppercase", fam.Prefix)
		}
		if !strings.HasSuffix(fam.Prefix, "-") {
			t.Errorf("family %q: prefix must end in '-' so it cannot match a longer family name", fam.Prefix)
		}
		if _, dup := seen[fam.Prefix]; dup {
			t.Errorf("family %q: declared twice", fam.Prefix)
		}
		seen[fam.Prefix] = struct{}{}
		switch fam.Confidence {
		case ConfidenceDefinitive, ConfidenceHeuristic, ConfidenceCorrelated:
		default:
			t.Errorf("family %q: invalid confidence %q", fam.Prefix, fam.Confidence)
		}
	}
}

// TestDefinitiveFamiliesGateOrExplain is the regression test for the fail-open
// gate. A family that presents findings at full confidence must be able to fail
// a build, or must say in the table why it cannot. Splitting confidence and gate
// eligibility across two unrelated slices is what let HIGH/definitive CLOUD-ID
// and POL-GHA findings pass a `--fail-on high` run silently.
func TestDefinitiveFamiliesGateOrExplain(t *testing.T) {
	for _, fam := range ruleFamilies {
		if fam.Confidence != ConfidenceDefinitive {
			continue
		}
		if fam.GatesInDeveloper {
			continue
		}
		if strings.TrimSpace(fam.UngatedReason) == "" {
			t.Errorf(
				"family %q is definitive but does not gate in developer mode and gives no UngatedReason; "+
					"either set GatesInDeveloper or document why it cannot gate",
				fam.Prefix,
			)
		}
	}
}

// TestUngatedReasonOnlyOnUngatedFamilies keeps the field from drifting into
// decoration once a family starts gating.
func TestUngatedReasonOnlyOnUngatedFamilies(t *testing.T) {
	for _, fam := range ruleFamilies {
		if fam.GatesInDeveloper && strings.TrimSpace(fam.UngatedReason) != "" {
			t.Errorf("family %q gates but carries an UngatedReason; remove it", fam.Prefix)
		}
	}
}

// ruleIDLiteral matches a rule ID written as a Go string literal, e.g. "CI-PRT-001".
var ruleIDLiteral = regexp.MustCompile(`"([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[A-Z0-9]+)"`)

// TestEveryRuleFamilyIsEmitted asserts that some non-test source in the tree
// actually produces a rule ID in each declared family.
//
// Three families (CI-MUTABLE-, CI-EXEC-, NON-CODE-) sat in the confidence and
// gate tables — and in the README, AGENTS.md, and CHANGELOG — with no rule
// emitting them, which made the developer gate look broader than it was. This
// test is deliberately source-level rather than fixture-level: a fixture-driven
// check only proves a family fires on the cases someone remembered to write.
func TestEveryRuleFamilyIsEmitted(t *testing.T) {
	root := repoRoot(t)
	emitted := collectRuleIDLiterals(t, root)

	for _, fam := range ruleFamilies {
		found := false
		for id := range emitted {
			if strings.HasPrefix(id, fam.Prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf(
				"family %q is declared in ruleFamilies but no non-test source emits a rule ID with that prefix; "+
					"remove the family or ship a rule that emits it",
				fam.Prefix,
			)
		}
	}
}

// collectRuleIDLiterals scans non-test Go sources under internal/ and cmd/ for
// rule-ID string literals.
func collectRuleIDLiterals(t *testing.T, root string) map[string]struct{} {
	t.Helper()
	out := make(map[string]struct{}, 512)
	for _, dir := range []string{"internal", "cmd"} {
		walkErr := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			// model.go holds the table itself; counting it would make the test tautological.
			if filepath.Base(path) == "model.go" && filepath.Base(filepath.Dir(path)) == "model" {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, m := range ruleIDLiteral.FindAllStringSubmatch(string(data), -1) {
				out[m[1]] = struct{}{}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk %s: %v", dir, walkErr)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no rule ID literals; the scan is broken, not the table")
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// internal/model -> repo root
	root := filepath.Join(wd, "..", "..")
	if _, statErr := os.Stat(filepath.Join(root, "go.mod")); statErr != nil {
		t.Fatalf("could not locate repo root from %s: %v", wd, statErr)
	}
	return root
}

func TestGateSuppressedRuleIDs(t *testing.T) {
	findings := []Finding{
		{RuleID: "ATK-EXE-001", Severity: SeverityHigh},
		{RuleID: "ATK-EXE-001", Severity: SeverityHigh}, // duplicate, reported once
		{RuleID: "SCM-TRUST-001", Severity: SeverityHigh},
		{RuleID: "BHV-SUPPLY-001", Severity: SeverityLow},                     // below threshold
		{RuleID: "ENC-ENTROPY-001", Severity: SeverityHigh, Suppressed: true}, // waived
		{RuleID: "OBF-CMD-002", Severity: SeverityCritical},
	}

	got := GateSuppressedRuleIDs(findings, SeverityHigh, ScanModeDeveloper)
	want := []string{"ATK-EXE-001", "OBF-CMD-002"}
	if len(got) != len(want) {
		t.Fatalf("GateSuppressedRuleIDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("GateSuppressedRuleIDs[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	if ids := GateSuppressedRuleIDs(findings, SeverityNone, ScanModeDeveloper); ids != nil {
		t.Errorf("fail-on none should suppress nothing, got %v", ids)
	}
	if ids := GateSuppressedRuleIDs(findings, SeverityHigh, ""); ids != nil {
		t.Errorf("empty mode gates everything, so nothing is suppressed; got %v", ids)
	}
}

package rules

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// literalHintQualityExempt lists content rules where no substring of length ≥3 is guaranteed
// in every match (alternation-only openings, two-byte hints like \x or ${, pure Unicode classes,
// high-entropy classes, etc.). Those keep LiteralHint empty; the scan worker treats empty hint
// as always eligible for regex.
var literalHintQualityExempt = map[string]bool{
	"OBF-ENT-001":   true, // [A-Za-z0-9+/=]{40,}
	"CI-GOV-003":    true,
	"ENC-EXFIL-002": true, // \xNN — hint shorter than 3 without false negatives
	"ENC-EXFIL-006": true,
	"OBF-CMD-001":   true,
	"OBF-CMD-004":   true, // ${ is two bytes
	"OBF-CMD-005":   true,
	"OBF-CMD-008":   true,
	"RUGPULL-002":   true,
	"RUGPULL-003":   true,
	"RUGPULL-004":   true,
	"CI-ENV-006":    true,
	"AGT-SKL-001":   true,
	"AGT-SKL-002":   true,
	"AGT-SKL-013":   true,
	"AGT-MCP-002":   true,
	"AGT-MCP-004":   true,
	"AGT-MEM-001":   true,
	"AGT-ART-005":   true,
	"AGT-ART-006":   true,
	"AGT-ART-011":   true,
	"AGT-TRUST-001": true,
	"AGT-TRUST-004": true,
	"AGT-TRUST-007": true,
	"AGT-TRUST-009": true,
	"AGT-TRUST-010": true,
	"AGT-TRUST-011": true,
	"AGT-TRUST-012": true,
	"AGT-TRUST-013": true,
	"AGT-TRUST-014": true,
	"AGT-TRUST-015": true,
	"AGT-TRUST-017": true,
	"AGT-TRUST-018": true,
	"ATK-LAT-003":   true,
	"CLOUD-ID-001":  true, // write-all | AdministratorAccess | Owner | … — no shared trigram
	"CLOUD-ID-002":  true, // (token…|oidc|federated).*(repo:|subject:|…) — no universal trigram
	"AGT-TRUST-002": true,
	"AGT-TRUST-008": true,
}

func TestLiteralHintQuality(t *testing.T) {
	rules := DefaultRules()
	var shortHints []string
	for _, r := range rules {
		if r.Target != TargetContent {
			continue
		}
		if literalHintQualityExempt[r.ID] {
			continue
		}
		hint := r.LiteralHint
		if hint == "" {
			hint = ExtractLiteralHint(r.Pattern)
		}
		if len(hint) < 3 {
			shortHints = append(shortHints, fmt.Sprintf("%s (hint=%q, pattern=%s)", r.ID, hint, r.Pattern[:min(len(r.Pattern), 60)]))
		}
	}
	if len(shortHints) > 0 {
		t.Errorf("rules with LiteralHint < 3 chars (AC pre-filter degradation):\n%s", strings.Join(shortHints, "\n"))
	}
}

func TestDefaultRulesCompositionIncludesAllGroups(t *testing.T) {
	rules := DefaultRules()
	// Update this count when adding rules. Docs use "200+" and should not be updated.
	assertRuleCount(t, "DefaultRules", rules, 229)
	validateRuleSlice(t, "DefaultRules", rules,
		"ENC-EXFIL-001",
		"AGT-SKL-001",
		"AGT-TRUST-001",
		"SCM-TRUST-001",
		"SCM-TAG-001",
		"SCM-GIT-001",
		"IAC-TF-001",
		"CLOUD-ID-001",
		"ATK-EXE-001",
		"CI-DEPBOT-001",
		"CI-BUILD-001",
		"CI-ENV-001",
		"AGT-MCP-019",
		"AGT-SKL-017",
	)

	order := map[string]int{}
	for idx, rule := range rules {
		order[rule.ID] = idx
	}
	if order["ENC-EXFIL-001"] >= order["AGT-SKL-001"] ||
		order["AGT-SKL-001"] >= order["SCM-GIT-001"] ||
		order["SCM-GIT-001"] >= order["SCM-TRUST-001"] ||
		order["SCM-TRUST-001"] >= order["SCM-TAG-001"] ||
		order["SCM-TAG-001"] >= order["IAC-TF-001"] ||
		order["IAC-TF-001"] >= order["ATK-EXE-001"] {
		t.Fatalf("default rule grouping order is not deterministic by group boundary")
	}
}

func TestDefaultRulesIDUniqueness(t *testing.T) {
	rules := DefaultRules()
	counts := make(map[string]int, len(rules))
	for _, r := range rules {
		counts[r.ID]++
	}
	var dups []string
	for id, n := range counts {
		if n > 1 {
			dups = append(dups, fmt.Sprintf("%s x%d", id, n))
		}
	}
	if len(dups) > 0 {
		t.Fatalf("duplicate rule IDs: %s", strings.Join(dups, ", "))
	}
}

func TestDefaultRulesFieldIntegrity(t *testing.T) {
	rules := DefaultRules()
	for _, r := range rules {
		if r.ID == "" {
			t.Error("rule has empty ID")
		}
		if r.Title == "" {
			t.Errorf("%s: empty Title", r.ID)
		}
		if r.Description == "" {
			t.Errorf("%s: empty Description", r.ID)
		}
		if r.Category == "" {
			t.Errorf("%s: empty Category", r.ID)
		}
		if r.Pattern == "" {
			t.Errorf("%s: empty Pattern", r.ID)
		}
		if r.Target == "" {
			t.Errorf("%s: empty Target", r.ID)
		}
		if r.Target == TargetContent && r.RE == nil {
			t.Errorf("%s: content rule has nil RE", r.ID)
		}
		if r.Target == TargetPath && r.RE == nil {
			t.Errorf("%s: path rule has nil RE", r.ID)
		}
		dash := strings.Index(r.ID, "-")
		prefix := r.ID
		if dash >= 0 {
			prefix = r.ID[:dash]
		}
		for _, ch := range prefix {
			if unicode.IsLower(ch) {
				t.Errorf("%s: prefix segment %q must not contain lowercase letters", r.ID, prefix)
				break
			}
			if ch == ' ' {
				t.Errorf("%s: prefix segment must not contain spaces", r.ID)
				break
			}
		}
	}
}

func TestDefaultRulesPatternCompilation(t *testing.T) {
	for _, r := range DefaultRules() {
		if r.RE == nil {
			t.Fatalf("%s: RE is nil", r.ID)
		}
		_ = r.RE.MatchString("")
	}
}

func TestDefaultRulesGroupOrdering(t *testing.T) {
	rules := DefaultRules()
	// DefaultRules() concatenates multiple rule-group slices; some ID families intentionally appear
	// in more than one contiguous block. Those prefixes are allowlisted here; any other family
	// that starts a new run after a different family has appeared must not do so again.
	repeatableFamilies := map[string]bool{
		"AGT": true,
		"ATK": true,
		"BHV": true,
		"CI":  true,
		"DEP": true,
		"ENC": true,
		"IAC": true,
		"OBF": true,
		"RUG": true,
		"SCM": true,
	}
	var runs []string
	var current string
	for _, r := range rules {
		dash := strings.Index(r.ID, "-")
		prefix := r.ID
		if dash >= 0 {
			prefix = r.ID[:dash]
		}
		if prefix == current {
			continue
		}
		runs = append(runs, prefix)
		current = prefix
	}
	runCount := make(map[string]int)
	for _, p := range runs {
		runCount[p]++
	}
	for p, n := range runCount {
		if n > 1 && !repeatableFamilies[p] {
			t.Fatalf("rule family %q has %d non-contiguous runs (unexpected interleaving)", p, n)
		}
	}
}

func TestExtractLiteralHint(t *testing.T) {
	tests := []struct {
		pattern string
		check   func(t *testing.T, hint string)
	}{
		{
			pattern: `(?i)curl\s+https://`,
			check: func(t *testing.T, hint string) {
				t.Helper()
				// Longest top-level literal wins (here, https:// vs curl).
				if !strings.Contains(hint, "https") && !strings.Contains(hint, "curl") {
					t.Fatalf("expected hint to mention curl or https, got %q", hint)
				}
			},
		},
		{
			pattern: `(?i)\b(bash|sh|zsh)\b`,
			check: func(t *testing.T, hint string) {
				t.Helper()
				// Literals inside a parenthesized alternation group are skipped; no extractable literal.
				if hint != "" {
					t.Errorf("expected empty hint (alternation-only group), got %q", hint)
				}
			},
		},
		{
			pattern: `[A-Za-z0-9+/=]{40,}`,
			check: func(t *testing.T, hint string) {
				t.Helper()
				if hint != "" {
					t.Fatalf("expected empty hint for character-class-only pattern, got %q", hint)
				}
			},
		},
		{
			pattern: `powershell(?:\.exe)?`,
			check: func(t *testing.T, hint string) {
				t.Helper()
				if !strings.Contains(hint, "powershell") {
					t.Fatalf("expected hint containing powershell, got %q", hint)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			hint := ExtractLiteralHint(tt.pattern)
			tt.check(t, hint)
		})
	}
}

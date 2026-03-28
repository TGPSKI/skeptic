package model

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in      string
		want    Severity
		wantErr bool
	}{
		{in: "info", want: SeverityInfo},
		{in: "low", want: SeverityLow},
		{in: "medium", want: SeverityMedium},
		{in: "high", want: SeverityHigh},
		{in: "critical", want: SeverityCritical},
		{in: "none", want: SeverityNone},
		{in: "  HIGH  ", want: SeverityHigh},
		{in: "CRITICAL", want: SeverityCritical},
		{in: "bogus", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseSeverity(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseSeverity(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSeverity(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSeverityWeight(t *testing.T) {
	if SeverityWeight(SeverityNone) != 0 {
		t.Error("none should be 0")
	}
	if SeverityWeight(SeverityCritical) <= SeverityWeight(SeverityHigh) {
		t.Error("critical should rank above high")
	}
	if SeverityWeight(Severity("unknown")) != 0 {
		t.Error("unknown severity should default to 0")
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		in      string
		want    ScanProfile
		wantErr bool
	}{
		{in: "repo", want: ProfileRepo},
		{in: "developer", want: ProfileDeveloper},
		{in: "container", want: ProfileContainer},
		{in: "fullfs", want: ProfileFullFS},
		{in: "  Repo  ", want: ProfileRepo},
		{in: "bogus", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseProfile(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseProfile(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseProfile(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseProfile(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCompactSnippet(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "short", in: "hello world", want: "hello world"},
		{name: "whitespace", in: "  hello   world  ", want: "hello world"},
		{name: "empty", in: "", want: ""},
		{name: "tabs_newlines", in: "\t hello \n world \t", want: "hello world"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompactSnippet(tt.in)
			if got != tt.want {
				t.Errorf("CompactSnippet(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	got := CompactSnippet(string(long))
	if len(got) != 203 { // 200 + "..."
		t.Errorf("long snippet length = %d, want 203", len(got))
	}
}

func TestSortedMapKeys(t *testing.T) {
	m := map[string]struct{}{"c": {}, "a": {}, "b": {}}
	keys := SortedMapKeys(m)
	if len(keys) != 3 || keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Errorf("SortedMapKeys = %v, want [a b c]", keys)
	}
	empty := SortedMapKeys(map[string]struct{}{})
	if len(empty) != 0 {
		t.Error("SortedMapKeys of empty map should be empty")
	}
}

func TestExpandHomePath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "tilde_only", in: "~", want: home},
		{name: "tilde_slash", in: "~/foo/bar", want: filepath.Join(home, "foo/bar")},
		{name: "no_tilde", in: "/usr/local", want: "/usr/local"},
		{name: "relative", in: "foo/bar", want: "foo/bar"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExpandHomePath(tt.in)
			if got != tt.want {
				t.Errorf("ExpandHomePath(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseScanStyle(t *testing.T) {
	tests := []struct {
		in      string
		want    ScanStyle
		wantErr bool
	}{
		{in: "", want: ScanStylePattern},
		{in: "pattern", want: ScanStylePattern},
		{in: "behavior", want: ScanStyleBehavior},
		{in: "hybrid", want: ScanStyleHybrid},
		{in: "unknown", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseScanStyle(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("expected error for %q", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseScanStyle(%q) error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseScanStyle(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseThreatMode(t *testing.T) {
	tests := []struct {
		in      string
		want    ThreatMode
		wantErr bool
	}{
		{in: "", want: ThreatModeAll},
		{in: "all", want: ThreatModeAll},
		{in: "machine-identity", want: ThreatModeMachineIdentity},
		{in: "ai-workload", want: ThreatModeAIWorkload},
		{in: "other", wantErr: true},
	}
	for _, tt := range tests {
		got, err := ParseThreatMode(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("expected error for %q", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseThreatMode(%q) error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseThreatMode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDefaultConfidenceForRuleID(t *testing.T) {
	tests := []struct {
		ruleID string
		want   ConfidenceClass
	}{
		// Definitive — every prefix in definitiveRulePrefixes
		{"AGT-TRUST-007", ConfidenceDefinitive},
		{"AGT-MEM-001", ConfidenceDefinitive},
		{"AGT-OUT-001", ConfidenceDefinitive},
		{"CI-MUTABLE-001", ConfidenceDefinitive},
		{"CI-PRT-001", ConfidenceDefinitive},
		{"CI-EXEC-001", ConfidenceDefinitive},
		{"GRAPH-003", ConfidenceDefinitive},
		{"CLOUD-ID-001", ConfidenceDefinitive},
		{"DISC-MCP-001", ConfidenceDefinitive},
		{"SCM-TRUST-001", ConfidenceDefinitive},
		{"NON-CODE-001", ConfidenceDefinitive},

		// Heuristic — broader pattern/behavioral families fall through
		{"AGT-SKL-003", ConfidenceHeuristic},
		{"AGT-MCP-006", ConfidenceHeuristic},
		{"ATK-EXE-001", ConfidenceHeuristic},
		{"BHV-SUPPLY-001", ConfidenceHeuristic},
		{"ENC-OBFUSC-001", ConfidenceHeuristic},
		{"DEP-TYPO-001", ConfidenceHeuristic},
		{"ENC-ENTROPY-001", ConfidenceHeuristic},
		{"DOM-TYPO-002", ConfidenceHeuristic},

		// Correlated — correlation/drift prefixes
		{"COR-001", ConfidenceCorrelated},
		{"COR-004", ConfidenceCorrelated},
		{"DRIFT-001", ConfidenceCorrelated},
		{"DRIFT-TREND-001", ConfidenceCorrelated},

		// Edge cases
		{"", ConfidenceHeuristic},
		{"agt-trust-007", ConfidenceDefinitive}, // case-insensitive
		{"cor-001", ConfidenceCorrelated},
	}
	for _, tt := range tests {
		got := DefaultConfidenceForRuleID(tt.ruleID)
		if got != tt.want {
			t.Errorf("DefaultConfidenceForRuleID(%q) = %q, want %q", tt.ruleID, got, tt.want)
		}
	}
}

func TestIsGateEligible(t *testing.T) {
	tests := []struct {
		ruleID string
		mode   ScanMode
		want   bool
	}{
		// Developer mode — wedge families are eligible
		{"AGT-TRUST-001", ScanModeDeveloper, true},
		{"AGT-SKL-003", ScanModeDeveloper, true},
		{"AGT-MCP-006", ScanModeDeveloper, true},
		{"AGT-MEM-001", ScanModeDeveloper, true},
		{"AGT-OUT-001", ScanModeDeveloper, true},
		{"CI-MUTABLE-001", ScanModeDeveloper, true},
		{"CI-PRT-001", ScanModeDeveloper, true},
		{"CI-EXEC-001", ScanModeDeveloper, true},
		{"GRAPH-003", ScanModeDeveloper, true},
		{"DISC-MCP-001", ScanModeDeveloper, true},
		{"DOM-TYPO-002", ScanModeDeveloper, true},
		{"SCM-TRUST-001", ScanModeDeveloper, true},

		// Developer mode — non-wedge families are ineligible
		{"ATK-EXE-001", ScanModeDeveloper, false},
		{"BHV-SUPPLY-001", ScanModeDeveloper, false},
		{"ENC-OBFUSC-001", ScanModeDeveloper, false},
		{"ENC-ENTROPY-001", ScanModeDeveloper, false},
		{"COR-001", ScanModeDeveloper, false},
		{"CLOUD-ID-001", ScanModeDeveloper, false},
		{"NON-CODE-001", ScanModeDeveloper, false},

		// IR and deep — nothing is gate-eligible
		{"AGT-TRUST-001", ScanModeIR, false},
		{"SCM-TRUST-001", ScanModeIR, false},
		{"ATK-EXE-001", ScanModeIR, false},
		{"AGT-TRUST-001", ScanModeDeep, false},
		{"SCM-TRUST-001", ScanModeDeep, false},

		// Empty mode — backward compat, everything eligible
		{"AGT-TRUST-001", "", true},
		{"ATK-EXE-001", "", true},
		{"COR-001", "", true},
	}
	for _, tt := range tests {
		got := IsGateEligible(tt.ruleID, tt.mode)
		if got != tt.want {
			t.Errorf("IsGateEligible(%q, %q) = %v, want %v", tt.ruleID, tt.mode, got, tt.want)
		}
	}
}

func TestFilterFindingsByMode(t *testing.T) {
	findings := []Finding{
		{RuleID: "AGT-TRUST-007", Severity: SeverityLow, ConfidenceClass: ConfidenceDefinitive},
		{RuleID: "ATK-EXE-001", Severity: SeverityHigh, ConfidenceClass: ConfidenceHeuristic},
		{RuleID: "BHV-SUPPLY-001", Severity: SeverityCritical, ConfidenceClass: ConfidenceHeuristic},
		{RuleID: "COR-001", Severity: SeverityMedium, ConfidenceClass: ConfidenceCorrelated},
		{RuleID: "ENC-OBFUSC-001", Severity: SeverityMedium, ConfidenceClass: ConfidenceHeuristic},
	}

	t.Run("developer", func(t *testing.T) {
		out := FilterFindingsByMode(findings, ScanModeDeveloper)
		ids := make(map[string]bool)
		for _, f := range out {
			ids[f.RuleID] = true
		}
		if !ids["AGT-TRUST-007"] {
			t.Error("definitive finding should pass regardless of severity")
		}
		if !ids["COR-001"] {
			t.Error("correlated finding should pass regardless of severity")
		}
		if !ids["BHV-SUPPLY-001"] {
			t.Error("heuristic critical finding should pass")
		}
		if ids["ATK-EXE-001"] {
			t.Error("heuristic high finding should be filtered in developer mode")
		}
		if ids["ENC-OBFUSC-001"] {
			t.Error("heuristic medium finding should be filtered in developer mode")
		}
		if len(out) != 3 {
			t.Errorf("developer mode: got %d findings, want 3", len(out))
		}
	})

	t.Run("ir", func(t *testing.T) {
		out := FilterFindingsByMode(findings, ScanModeIR)
		if len(out) != len(findings) {
			t.Errorf("ir mode: got %d findings, want %d (all)", len(out), len(findings))
		}
	})

	t.Run("deep", func(t *testing.T) {
		out := FilterFindingsByMode(findings, ScanModeDeep)
		if len(out) != len(findings) {
			t.Errorf("deep mode: got %d findings, want %d (all)", len(out), len(findings))
		}
	})
}

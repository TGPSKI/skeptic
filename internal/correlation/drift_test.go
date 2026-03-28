package correlation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestBuildBehaviorProfile(t *testing.T) {
	findings := []model.Finding{
		{RuleID: "BHV-CI-001", Severity: model.SeverityHigh},
		{RuleID: "BHV-CI-001", Severity: model.SeverityHigh},
		{RuleID: "POL-GHA-001", Severity: model.SeverityMedium},
	}
	profile := BuildBehaviorProfile(findings, 100)
	if profile.ScannedFiles != 100 {
		t.Fatalf("expected ScannedFiles 100, got %d", profile.ScannedFiles)
	}
	if len(profile.BehaviorChainIDs) != 1 || profile.BehaviorChainIDs[0] != "BHV-CI-001" {
		t.Fatalf("unexpected chains: %v", profile.BehaviorChainIDs)
	}
	if profile.ProfileHash == "" {
		t.Fatal("expected non-empty hash")
	}
}

func TestComputeDrift(t *testing.T) {
	prev := BehaviorProfile{
		BehaviorChainIDs: []string{"BHV-CI-001", "BHV-EXFIL-001"},
		PolicyCheckIDs:   []string{"POL-GHA-001"},
		SeverityDist:     map[string]int{"high": 5, "medium": 3},
	}
	curr := BehaviorProfile{
		BehaviorChainIDs: []string{"BHV-CI-001", "BHV-AGENT-001"},
		PolicyCheckIDs:   []string{"POL-GHA-001", "POL-TOK-002"},
		SeverityDist:     map[string]int{"high": 5, "medium": 3},
	}
	dr := ComputeDrift(curr, prev, DefaultDriftConfig())
	if len(dr.NewChains) != 1 || dr.NewChains[0] != "BHV-AGENT-001" {
		t.Fatalf("expected BHV-AGENT-001 as new, got %v", dr.NewChains)
	}
	if len(dr.DisappearedChains) != 1 || dr.DisappearedChains[0] != "BHV-EXFIL-001" {
		t.Fatalf("expected BHV-EXFIL-001 as disappeared, got %v", dr.DisappearedChains)
	}
	if len(dr.NewPolicies) != 1 || dr.NewPolicies[0] != "POL-TOK-002" {
		t.Fatalf("expected POL-TOK-002 as new policy, got %v", dr.NewPolicies)
	}
}

func TestDriftToFindings(t *testing.T) {
	dr := DriftReport{
		NewChains:     []string{"BHV-AGENT-001"},
		NewPolicies:   []string{"POL-NEW-001"},
		SeverityShift: true,
		ShiftDetail:   "high: 2 -> 10",
	}
	findings := DriftToFindings(dr)
	if len(findings) < 3 {
		t.Fatalf("expected at least 3 findings, got %d", len(findings))
	}
	var drift004 bool
	for _, f := range findings {
		if f.RuleID == "DRIFT-004" {
			drift004 = true
			if f.Severity != model.SeverityMedium {
				t.Errorf("DRIFT-004 severity: got %s want medium", f.Severity)
			}
		}
	}
	if !drift004 {
		t.Fatal("expected DRIFT-004 for new policy")
	}
}

func TestSaveLoadBehaviorProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	profile := BehaviorProfile{
		BehaviorChainIDs: []string{"BHV-CI-001"},
		SeverityDist:     map[string]int{"high": 3},
		ProfileHash:      "abc123",
	}
	if err := SaveBehaviorProfile(path, profile); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBehaviorProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ProfileHash != "abc123" {
		t.Fatalf("expected hash abc123, got %s", loaded.ProfileHash)
	}
	_, err = LoadBehaviorProfile(filepath.Join(dir, "nonexistent"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	_ = os.Remove(path)
}

func TestProfileHistoryPush(t *testing.T) {
	h := ProfileHistory{MaxProfiles: 3}
	for i := range 5 {
		h.Push(BehaviorProfile{ProfileHash: string(rune('a' + i))})
	}
	if h.Len() != 3 {
		t.Fatalf("expected len 3, got %d", h.Len())
	}
	if h.Profiles[0].ProfileHash != "c" || h.Profiles[1].ProfileHash != "d" || h.Profiles[2].ProfileHash != "e" {
		t.Fatalf("unexpected FIFO eviction order: %#v", h.Profiles)
	}
}

func profileWithHigh(high, files int) BehaviorProfile {
	return BehaviorProfile{
		Version:      BehaviorProfileVersion,
		SeverityDist: map[string]int{"critical": 0, "high": high, "medium": 0, "low": 0, "info": 0},
		ScannedFiles: files,
	}
}

func TestComputeTrendMonotonic(t *testing.T) {
	var h ProfileHistory
	for _, high := range []int{1, 2, 3, 4} {
		h.Push(profileWithHigh(high, 1000))
	}
	out := h.ComputeTrend()
	var trend []model.Finding
	for _, f := range out {
		if f.RuleID == "DRIFT-TREND-001" {
			trend = append(trend, f)
		}
	}
	if len(trend) != 1 {
		t.Fatalf("expected exactly one DRIFT-TREND-001, got %d (%v)", len(trend), trend)
	}
	if !strings.Contains(trend[0].Match, "severity=high") {
		t.Fatalf("expected high severity trend, got %q", trend[0].Match)
	}
}

func TestComputeTrendNoTrend(t *testing.T) {
	var h ProfileHistory
	for _, high := range []int{1, 5, 2, 6} {
		h.Push(profileWithHigh(high, 1000))
	}
	out := h.ComputeTrend()
	for _, f := range out {
		if f.RuleID == "DRIFT-TREND-001" {
			t.Fatalf("unexpected trend finding: %v", f)
		}
	}
}

func TestSaveLoadProfileHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.json")
	h := ProfileHistory{MaxProfiles: 5, Profiles: []BehaviorProfile{{ProfileHash: "x"}}}
	if err := SaveProfileHistory(path, h); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProfileHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.MaxProfiles != 5 || len(loaded.Profiles) != 1 || loaded.Profiles[0].ProfileHash != "x" {
		t.Fatalf("unexpected loaded history: %+v", loaded)
	}
}

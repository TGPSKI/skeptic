package suppress

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestLoadWaiverFile_valid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "waivers.json")
	content := `{
  "version": 1,
  "waivers": [
    {
      "rule_id": "CLOUD-ID-001",
      "reason": "documented exception",
      "author": "alice"
    }
  ]
}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	wf, err := LoadWaiverFile(p)
	if err != nil {
		t.Fatalf("LoadWaiverFile: %v", err)
	}
	if wf.Version != 1 || len(wf.Waivers) != 1 {
		t.Fatalf("unexpected wf: %+v", wf)
	}
	if wf.Waivers[0].RuleID != "CLOUD-ID-001" || wf.Waivers[0].Reason != "documented exception" {
		t.Fatalf("waiver: %+v", wf.Waivers[0])
	}
}

func TestLoadWaiverFile_missingFile(t *testing.T) {
	t.Parallel()
	_, err := LoadWaiverFile(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadWaiverFile_invalidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(p, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadWaiverFile(p)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadWaiverFile_missingReason(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "waivers.json")
	content := `{"version":1,"waivers":[{"rule_id":"R-1","reason":""}]}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadWaiverFile(p)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadWaiverFile_missingRuleID(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "waivers.json")
	content := `{"version":1,"waivers":[{"rule_id":"  ","reason":"x"}]}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadWaiverFile(p)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadWaiverFile_invalidExpiresAt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "waivers.json")
	content := `{"version":1,"waivers":[{"rule_id":"R-1","reason":"ok","expires_at":"not-a-date"}]}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadWaiverFile(p)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadWaiverFile_versionTooLow(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "waivers.json")
	content := `{"version":0,"waivers":[{"rule_id":"R-1","reason":"ok"}]}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadWaiverFile(p)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIsWaived_exactMatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "CLOUD-ID-001", File: "a.go"}
	w := []Waiver{{RuleID: "CLOUD-ID-001", Reason: "exact"}}
	ok, reason := IsWaived(f, w, now, nil)
	if !ok || reason != "exact" {
		t.Fatalf("got %v %q", ok, reason)
	}
}

func TestIsWaived_prefixGlob(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "CLOUD-ID-042", File: "x.go"}
	w := []Waiver{{RuleID: "CLOUD-ID-*", Reason: "glob"}}
	ok, reason := IsWaived(f, w, now, nil)
	if !ok || reason != "glob" {
		t.Fatalf("got %v %q", ok, reason)
	}
}

func TestIsWaived_prefixWithoutGlob(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "CLOUD-ID-042", File: "x.go"}
	w := []Waiver{{RuleID: "CLOUD-", Reason: "prefix"}}
	ok, reason := IsWaived(f, w, now, nil)
	if !ok || reason != "prefix" {
		t.Fatalf("got %v %q", ok, reason)
	}
}

func TestIsWaived_ruleGlobPattern(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "BHV-FOO-001", File: "x.go"}
	w := []Waiver{{RuleID: "BHV-*-001", Reason: "mid-glob"}}
	ok, reason := IsWaived(f, w, now, nil)
	if !ok || reason != "mid-glob" {
		t.Fatalf("got %v %q", ok, reason)
	}
}

func TestIsWaived_filePathMatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "R-1", File: "pkg/foo/bar.go"}
	w := []Waiver{{RuleID: "R-1", FilePath: "pkg/*/*.go", Reason: "path"}}
	ok, reason := IsWaived(f, w, now, nil)
	if !ok || reason != "path" {
		t.Fatalf("got %v %q", ok, reason)
	}
}

func TestIsWaived_filePathMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "R-1", File: "other/baz.go"}
	w := []Waiver{{RuleID: "R-1", FilePath: "pkg/*", Reason: "path"}}
	ok, _ := IsWaived(f, w, now, nil)
	if ok {
		t.Fatal("expected no match")
	}
}

func TestIsWaived_expiredWaiver(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "R-1", File: "a.go"}
	w := []Waiver{{
		RuleID:    "R-1",
		Reason:    "tmp",
		ExpiresAt: "2026-03-01T00:00:00Z",
	}}
	ok, _ := IsWaived(f, w, now, nil)
	if ok {
		t.Fatal("expected expired waiver to be skipped")
	}
}

func TestIsWaived_noMatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "OTHER-001", File: "a.go"}
	w := []Waiver{{RuleID: "CLOUD-*", Reason: "nope"}}
	ok, reason := IsWaived(f, w, now, nil)
	if ok || reason != "" {
		t.Fatalf("got %v %q", ok, reason)
	}
}

func TestIsWaived_emptyFilePathMatchesAll(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "R-1", File: "any/where.go"}
	w := []Waiver{{RuleID: "R-1", Reason: "all files"}}
	ok, reason := IsWaived(f, w, now, nil)
	if !ok || reason != "all files" {
		t.Fatalf("got %v %q", ok, reason)
	}
}

func TestIsWaived_SHA256Match(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(fp, []byte("content-abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "R-1", File: fp}
	hashes := ComputeFileHashes([]model.Finding{f})
	w := []Waiver{{RuleID: "R-1", FileSHA256: hashes[fp], Reason: "pinned"}}
	ok, reason := IsWaived(f, w, now, hashes)
	if !ok || reason != "pinned" {
		t.Fatalf("expected SHA256-pinned match, got %v %q", ok, reason)
	}
}

func TestIsWaived_SHA256Mismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(fp, []byte("content-abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "R-1", File: fp}
	hashes := ComputeFileHashes([]model.Finding{f})
	w := []Waiver{{RuleID: "R-1", FileSHA256: "deadbeef00000000000000000000000000000000000000000000000000000000", Reason: "stale"}}
	ok, _ := IsWaived(f, w, now, hashes)
	if ok {
		t.Fatal("expected SHA256 mismatch to reject waiver")
	}
}

func TestIsWaived_SHA256OmittedBackwardCompat(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	f := model.Finding{RuleID: "R-1", File: "any.go"}
	w := []Waiver{{RuleID: "R-1", Reason: "no pin"}}
	ok, reason := IsWaived(f, w, now, nil)
	if !ok || reason != "no pin" {
		t.Fatalf("waiver without SHA256 should match regardless, got %v %q", ok, reason)
	}
}

func TestComputeFileHashes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	fp1 := filepath.Join(dir, "a.txt")
	fp2 := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(fp1, []byte("aaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fp2, []byte("bbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings := []model.Finding{
		{RuleID: "R-1", File: fp1},
		{RuleID: "R-2", File: fp2},
		{RuleID: "R-3", File: fp1},
		{RuleID: "COR-001", File: "(correlation)"},
	}
	hashes := ComputeFileHashes(findings)
	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(hashes))
	}
	if hashes[fp1] == "" || hashes[fp2] == "" {
		t.Fatalf("missing hashes: %v", hashes)
	}
	if _, ok := hashes["(correlation)"]; ok {
		t.Fatal("synthetic path should be skipped")
	}
}

func TestApplyWaivers(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{
		{RuleID: "A-001", File: "x.go"},
		{RuleID: "B-1", File: "README.md"},
		{RuleID: "B-1", File: "main.go"},
		{RuleID: "C-1", File: "z.go"},
	}
	waivers := []Waiver{
		{RuleID: "A-*", Reason: "waived A family"},
		{RuleID: "B-1", FilePath: "*.md", Reason: "docs only"},
	}
	got := ApplyWaivers(findings, waivers, nil)
	if len(got) != len(findings) {
		t.Fatalf("len %d want %d", len(got), len(findings))
	}
	if !got[0].Suppressed || got[0].SuppressionReason != "waived A family" {
		t.Fatalf("finding 0: %+v", got[0])
	}
	if !got[1].Suppressed || got[1].SuppressionReason != "docs only" {
		t.Fatalf("finding 1: %+v", got[1])
	}
	if got[2].Suppressed {
		t.Fatalf("finding 2 should not be suppressed: %+v", got[2])
	}
	if got[3].Suppressed {
		t.Fatalf("finding 3 should not be suppressed: %+v", got[3])
	}
}

// Package suppress loads waiver files and matches findings against suppression rules.
package suppress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// Waiver describes a single suppression entry in a waiver file.
type Waiver struct {
	RuleID      string   `json:"rule_id"`
	FilePath    string   `json:"file_path,omitempty"`
	FileSHA256  string   `json:"file_sha256,omitempty"`  // hex-encoded; waiver invalid if file content changes
	FindingKeys []string `json:"finding_keys,omitempty"` // accepted stable identities used by refresh review
	Reason      string   `json:"reason"`
	ExpiresAt   string   `json:"expires_at,omitempty"` // RFC3339 format, empty = never
	Author      string   `json:"author,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"` // RFC3339 format
}

// WaiverFile is the top-level JSON document for waivers.
type WaiverFile struct {
	Version int      `json:"version"`
	Waivers []Waiver `json:"waivers"`
}

// LoadWaiverFile reads path, unmarshals JSON, and validates waiver entries.
func LoadWaiverFile(path string) (WaiverFile, error) {
	var wf WaiverFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return wf, fmt.Errorf("read waiver file: %w", err)
	}
	if err := json.Unmarshal(raw, &wf); err != nil {
		return wf, fmt.Errorf("parse waiver file: %w", err)
	}
	if wf.Version < 1 {
		return wf, fmt.Errorf("waiver file version must be >= 1, got %d", wf.Version)
	}
	for i := range wf.Waivers {
		w := &wf.Waivers[i]
		w.RuleID = strings.TrimSpace(w.RuleID)
		w.Reason = strings.TrimSpace(w.Reason)
		w.FilePath = strings.TrimSpace(w.FilePath)
		if w.RuleID == "" {
			return wf, fmt.Errorf("waiver %d: rule_id is required", i)
		}
		if w.Reason == "" {
			return wf, fmt.Errorf("waiver %d: reason is required", i)
		}
		if w.ExpiresAt != "" {
			if _, err := time.Parse(time.RFC3339, w.ExpiresAt); err != nil {
				return wf, fmt.Errorf("waiver %d: invalid expires_at %q: %w", i, w.ExpiresAt, err)
			}
		}
		if w.CreatedAt != "" {
			if _, err := time.Parse(time.RFC3339, w.CreatedAt); err != nil {
				return wf, fmt.Errorf("waiver %d: invalid created_at %q: %w", i, w.CreatedAt, err)
			}
		}
	}
	return wf, nil
}

func waiverActive(w Waiver, now time.Time) bool {
	if w.ExpiresAt == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, w.ExpiresAt)
	if err != nil {
		return false
	}
	return t.After(now)
}

func ruleIDMatches(pattern, ruleID string) bool {
	if pattern == ruleID {
		return true
	}
	if strings.ContainsAny(pattern, "*?[]") {
		ok, err := filepath.Match(pattern, ruleID)
		if err != nil {
			return false
		}
		return ok
	}
	return strings.HasPrefix(ruleID, pattern)
}

func filePathMatches(pattern, file string) bool {
	if pattern == "" {
		return true
	}
	ok, err := filepath.Match(pattern, file)
	if err != nil {
		return false
	}
	return ok
}

// IsWaived reports whether f is covered by any active waiver in waivers.
// fileHashes maps file paths to hex-encoded SHA256 digests. When a waiver
// specifies FileSHA256, the waiver only matches if the file's current hash
// agrees. The first matching waiver wins. Returns (true, reason) when suppressed.
func IsWaived(f model.Finding, waivers []Waiver, now time.Time, fileHashes map[string]string) (bool, string) {
	for _, w := range waivers {
		if w.Reason == "" {
			continue
		}
		if !waiverActive(w, now) {
			continue
		}
		if !ruleIDMatches(w.RuleID, f.RuleID) {
			continue
		}
		if !filePathMatches(w.FilePath, f.File) {
			continue
		}
		if w.FileSHA256 != "" {
			actual, ok := fileHashes[f.File]
			if !ok || !strings.EqualFold(actual, w.FileSHA256) {
				continue
			}
		}
		return true, w.Reason
	}
	return false, ""
}

// ApplyWaivers returns a copy of findings with Suppressed and SuppressionReason
// set for entries matched by waivers. Findings are never removed.
// fileHashes maps file paths to hex-encoded SHA256 for content-pinned waivers.
func ApplyWaivers(findings []model.Finding, waivers []Waiver, fileHashes map[string]string) []model.Finding {
	now := time.Now()
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		ok, reason := IsWaived(out[i], waivers, now, fileHashes)
		if ok {
			for _, relatedID := range out[i].RelatedRuleIDs {
				related := out[i]
				related.RuleID = relatedID
				if relatedOK, _ := IsWaived(related, waivers, now, fileHashes); !relatedOK {
					ok = false
					break
				}
			}
		}
		if ok {
			out[i].Suppressed = true
			out[i].SuppressionReason = reason
		}
	}
	return out
}

// SuppressDerivedFindings suppresses a correlation only when every referenced
// constituent finding in its scope is suppressed. A waived chain should not
// remain as an unactionable aggregate, while any live constituent keeps the
// correlation visible.
func SuppressDerivedFindings(findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		if !strings.HasPrefix(out[i].RuleID, "COR-") || len(out[i].References) == 0 {
			continue
		}
		refs := make(map[string]struct{}, len(out[i].References))
		for _, id := range out[i].References {
			refs[id] = struct{}{}
		}
		matched := 0
		allSuppressed := true
		for j := range out {
			if i == j || strings.HasPrefix(out[j].RuleID, "COR-") || !findingInCorrelationScope(out[j], out[i].File) {
				continue
			}
			if _, ok := refs[out[j].RuleID]; !ok {
				continue
			}
			matched++
			if !out[j].Suppressed {
				allSuppressed = false
				break
			}
		}
		if matched > 0 && allSuppressed {
			out[i].Suppressed = true
			out[i].SuppressionReason = "all constituent findings are waived"
		}
	}
	return out
}

func findingInCorrelationScope(f model.Finding, scope string) bool {
	if scope == "(repo)" || scope == "(correlation)" || scope == "." || scope == "" {
		return true
	}
	cleanScope := strings.TrimSuffix(filepath.ToSlash(scope), "/")
	cleanFile := filepath.ToSlash(f.File)
	return cleanFile == cleanScope || strings.HasPrefix(cleanFile, cleanScope+"/")
}

// ComputeFileHashes returns a map of file path -> hex SHA256 for all unique
// real file paths referenced in findings. Synthetic paths (correlation, repo-level)
// and unreadable files are silently skipped.
func ComputeFileHashes(findings []model.Finding) map[string]string {
	seen := make(map[string]struct{})
	for _, f := range findings {
		seen[f.File] = struct{}{}
	}
	hashes := make(map[string]string, len(seen))
	for path := range seen {
		if path == "" || strings.HasPrefix(path, "(") {
			continue
		}
		h, err := security.SHA256FileHex(path)
		if err != nil {
			continue
		}
		hashes[path] = h
	}
	return hashes
}

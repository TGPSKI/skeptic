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

// ScanFunc runs a scan and returns the report. The callback pattern avoids
// importing cmd/skeptic or internal/scan from suppress.
type ScanFunc func(repoPath string) (*model.Report, error)

// WaiveOptions describes what to waive and where to write it.
type WaiveOptions struct {
	RepoPath   string
	File       string // relative path within repo; empty = all files
	RuleID     string // empty = all rules on matched files
	Reason     string
	WaiverPath string // explicit output path; resolved from config if empty
}

// WaiveResult summarizes the outcome.
type WaiveResult struct {
	TotalFindings   int      `json:"total_findings"`
	MatchedFindings int      `json:"matched_findings"`
	WaiversCreated  int      `json:"waivers_created"`
	WaiverPath      string   `json:"waiver_path"`
	FileSHA256      string   `json:"file_sha256,omitempty"`
	WaivedRuleIDs   []string `json:"waived_rule_ids"`
	ActiveAfter     int      `json:"active_after"`
	SuppressedAfter int      `json:"suppressed_after"`
}

// RunWaive scans, filters findings, generates SHA256-pinned waivers, writes
// them to disk, and returns a summary. The caller provides scanFn so this
// package never imports the scan engine directly.
func RunWaive(opts WaiveOptions, scanFn ScanFunc) (WaiveResult, error) {
	if opts.Reason == "" {
		return WaiveResult{}, fmt.Errorf("--reason is required")
	}
	if opts.File == "" && opts.RuleID == "" {
		return WaiveResult{}, fmt.Errorf("at least one of --file or --rule is required")
	}

	report, err := scanFn(opts.RepoPath)
	if err != nil {
		return WaiveResult{}, fmt.Errorf("scan failed: %w", err)
	}

	matched := filterFindings(report.Findings, opts.File, opts.RuleID)
	if len(matched) == 0 {
		return WaiveResult{
			TotalFindings: len(report.Findings),
		}, nil
	}

	newWaivers := buildWaivers(matched, opts)

	waiverPath := opts.WaiverPath
	if waiverPath == "" {
		waiverPath = ".skeptic-waivers.json"
	}

	if err := mergeAndWrite(waiverPath, newWaivers); err != nil {
		return WaiveResult{}, fmt.Errorf("write waivers: %w", err)
	}

	var sha string
	if opts.File != "" && len(newWaivers) > 0 {
		sha = newWaivers[0].FileSHA256
	}

	ruleIDs := make([]string, 0, len(newWaivers))
	for _, w := range newWaivers {
		ruleIDs = append(ruleIDs, w.RuleID)
	}

	wf, loadErr := LoadWaiverFile(waiverPath)
	var active, suppressed int
	if loadErr == nil {
		fileHashes := ComputeFileHashes(report.Findings)
		validated := ApplyWaivers(report.Findings, wf.Waivers, fileHashes)
		for _, f := range validated {
			if f.Suppressed {
				suppressed++
			} else {
				active++
			}
		}
	} else {
		active = len(report.Findings)
	}

	return WaiveResult{
		TotalFindings:   len(report.Findings),
		MatchedFindings: len(matched),
		WaiversCreated:  len(newWaivers),
		WaiverPath:      waiverPath,
		FileSHA256:      sha,
		WaivedRuleIDs:   ruleIDs,
		ActiveAfter:     active,
		SuppressedAfter: suppressed,
	}, nil
}

func filterFindings(findings []model.Finding, file, ruleID string) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		if file != "" && !matchesFile(f.File, file) {
			continue
		}
		if ruleID != "" && f.RuleID != ruleID {
			continue
		}
		out = append(out, f)
	}
	return out
}

func matchesFile(findingFile, target string) bool {
	if findingFile == target {
		return true
	}
	return filepath.Base(findingFile) == filepath.Base(target) &&
		strings.HasSuffix(findingFile, target)
}

func buildWaivers(findings []model.Finding, opts WaiveOptions) []Waiver {
	type key struct{ ruleID, file string }
	seen := make(map[key]struct{})
	var waivers []Waiver
	now := time.Now().UTC().Format(time.RFC3339)

	for _, f := range findings {
		k := key{f.RuleID, f.File}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}

		w := Waiver{
			RuleID:    f.RuleID,
			FilePath:  f.File,
			Reason:    opts.Reason,
			CreatedAt: now,
		}
		if f.File != "" && !strings.HasPrefix(f.File, "(") {
			if h, err := security.SHA256FileHex(f.File); err == nil {
				w.FileSHA256 = h
			}
		}
		waivers = append(waivers, w)
	}
	return waivers
}

func mergeAndWrite(path string, newWaivers []Waiver) error {
	var wf WaiverFile
	if raw, err := os.ReadFile(path); err == nil {
		if jsonErr := json.Unmarshal(raw, &wf); jsonErr != nil {
			return fmt.Errorf("parse existing waiver file: %w", jsonErr)
		}
	} else {
		wf.Version = 1
	}

	type key struct{ ruleID, file string }
	existing := make(map[key]int, len(wf.Waivers))
	for i, w := range wf.Waivers {
		existing[key{w.RuleID, w.FilePath}] = i
	}

	for _, nw := range newWaivers {
		k := key{nw.RuleID, nw.FilePath}
		if idx, ok := existing[k]; ok {
			wf.Waivers[idx].FileSHA256 = nw.FileSHA256
			wf.Waivers[idx].Reason = nw.Reason
			wf.Waivers[idx].CreatedAt = nw.CreatedAt
		} else {
			wf.Waivers = append(wf.Waivers, nw)
		}
	}

	data, err := json.MarshalIndent(wf, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o600)
}

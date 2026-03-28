package correlation

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
)

// GitCommitInfo holds metadata about a git commit associated with a finding.
type GitCommitInfo struct {
	Author string
	Date   string // ISO format
	Hash   string
}

const (
	gitCommandTimeout  = 5 * time.Second
	highSeverityWindow = 48 * time.Hour
)

// CorrelateByGitHistory groups findings by recent git commit author and flags
// clusters of high-severity changes by the same author within a time window.
// Returns nil if git is not available or the path is not a git repo.
func CorrelateByGitHistory(findings []model.Finding, repoRoot string) []model.Finding {
	if len(findings) == 0 {
		return nil
	}
	if _, err := exec.LookPath("git"); err != nil {
		return nil
	}
	repoRoot = filepath.Clean(repoRoot)
	ctx, cancel := context.WithTimeout(context.Background(), gitCommandTimeout)
	defer cancel()
	if !gitRepoOK(ctx, repoRoot) {
		return nil
	}

	commitByFile, err := gitCommitsForFindingFiles(context.Background(), repoRoot, findings)
	if err != nil || len(commitByFile) == 0 {
		return nil
	}

	byAuthor := make(map[string][]time.Time)
	for _, f := range findings {
		if !isHighSeverityFinding(f) || strings.TrimSpace(f.File) == "" {
			continue
		}
		info, ok := commitByFile[f.File]
		if !ok || info.Hash == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, info.Date)
		if err != nil {
			continue
		}
		byAuthor[info.Author] = append(byAuthor[info.Author], t)
	}

	var out []model.Finding
	for author, times := range byAuthor {
		if len(times) < 3 {
			continue
		}
		minT := times[0]
		maxT := times[0]
		for _, g := range times[1:] {
			if g.Before(minT) {
				minT = g
			}
			if g.After(maxT) {
				maxT = g
			}
		}
		if maxT.Sub(minT) > highSeverityWindow {
			continue
		}
		out = append(out, model.Finding{
			RuleID:          "COR-TEMPORAL-001",
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           "Cluster of high-severity changes by single author",
			Description:     fmt.Sprintf("%d high-severity findings are associated with commits by %q within a 48-hour window.", len(times), author),
			Category:        "correlation",
			Mitre:           "TA0001",
			Severity:        model.SeverityHigh,
			File:            "(git-history)",
			Match:           fmt.Sprintf("author=%q high_severity_findings=%d window_hours<=%.1f", author, len(times), highSeverityWindow.Hours()),
		})
	}
	return out
}

func isHighSeverityFinding(f model.Finding) bool {
	switch f.Severity {
	case model.SeverityHigh, model.SeverityCritical:
		return true
	default:
		return false
	}
}

func gitRepoOK(ctx context.Context, repoRoot string) bool {
	ctx, cancel := context.WithTimeout(ctx, gitCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", repoRoot, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

func gitCommitsForFindingFiles(parentCtx context.Context, repoRoot string, findings []model.Finding) (map[string]GitCommitInfo, error) {
	seen := make(map[string]struct{})
	var files []string
	for _, f := range findings {
		fp := strings.TrimSpace(f.File)
		if fp == "" {
			continue
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		files = append(files, fp)
	}
	out := make(map[string]GitCommitInfo, len(files))
	for _, fp := range files {
		rel, ok := filePathRelativeToRepo(repoRoot, fp)
		if !ok {
			continue
		}
		ctx, cancel := context.WithTimeout(parentCtx, gitCommandTimeout)
		cmd := exec.CommandContext(ctx, "git", "-C", repoRoot, "log", "-1", "--format=%H|%an|%aI", "--", rel)
		b, err := cmd.Output()
		cancel()
		if err != nil {
			continue
		}
		line := strings.TrimSpace(string(b))
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		out[fp] = GitCommitInfo{
			Hash:   strings.TrimSpace(parts[0]),
			Author: strings.TrimSpace(parts[1]),
			Date:   strings.TrimSpace(parts[2]),
		}
	}
	return out, nil
}

func filePathRelativeToRepo(repoRoot, file string) (string, bool) {
	repoRoot = filepath.Clean(repoRoot)
	var abs string
	if filepath.IsAbs(file) {
		abs = filepath.Clean(file)
	} else {
		abs = filepath.Clean(filepath.Join(repoRoot, file))
	}
	rel, err := filepath.Rel(repoRoot, abs)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

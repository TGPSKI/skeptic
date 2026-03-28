package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"

	"github.com/TGPSKI/skeptic/internal/model"
)

// CorrelationSpec defines a cross-finding pattern that detects multi-step attacks.
type CorrelationSpec struct {
	ID                      string
	Title                   string
	Description             string
	Severity                model.Severity
	RequiredFindingPatterns []string
}

// DefaultCorrelationSpecs defines the built-in cross-finding correlation patterns bundled with the scanner.
var DefaultCorrelationSpecs = []CorrelationSpec{
	{
		ID:          "COR-001",
		Title:       "Unpinned action + CI exfiltration chain",
		Description: "Unpinned GitHub Actions combined with CI exfiltration patterns suggest a supply chain compromise vector.",
		Severity:    model.SeverityCritical,
		RequiredFindingPatterns: []string{
			"POL-GHA-",
			"(BHV-CI-|CI-ABUSE-|ENC-EXFIL-)",
		},
	},
	{
		ID:          "COR-002",
		Title:       "Wildcard identity trust + lateral movement pattern",
		Description: "Overly broad identity trust combined with lateral movement indicators suggest an identity abuse chain.",
		Severity:    model.SeverityHigh,
		RequiredFindingPatterns: []string{
			"(SCM-TRUST-|MID-|CLOUD-ID-)",
			"(ATK-LAT-|BHV-CRED-)",
		},
	},
	{
		ID:          "COR-003",
		Title:       "MCP tool poisoning + data exfiltration behavior",
		Description: "MCP tool manipulation combined with exfiltration behavior indicates an agentic attack chain.",
		Severity:    model.SeverityCritical,
		RequiredFindingPatterns: []string{
			"(AGT-MCP-|AGT-SKL-|AGT-EXP-|DISC-MCP-)",
			"(ATK-COL-|BHV-EXFIL-|ENC-EXFIL-)",
		},
	},
	{
		ID:          "COR-004",
		Title:       "Skill poisoning + persistence across project boundaries",
		Description: "Agent skill manipulation in one directory combined with persistence artifacts in another suggests a coordinated agentic attack.",
		Severity:    model.SeverityCritical,
		RequiredFindingPatterns: []string{
			"AGT-SKL-",
			"ATK-PER-",
		},
	},
	{
		ID:          "COR-005",
		Title:       "Cloud identity exposure + MCP attack surface",
		Description: "Cloud identity findings combined with MCP attack surface indicators suggest a path from cloud credentials to agentic tool abuse.",
		Severity:    model.SeverityHigh,
		RequiredFindingPatterns: []string{
			"(CLOUD-ID-|MID-|GRAPH-)",
			"(AGT-MCP-|DISC-MCP-)",
		},
	},
	{
		ID:          "COR-006",
		Title:       "Dependency bot without release age gate + install hooks in repo",
		Description: "No minimumReleaseAge on Renovate/Dependabot config combined with package install hook definitions in the same repo. A compromised upstream package version triggers a Renovate PR within minutes — CI runs npm install/pip install on the PR branch, which executes the malicious install hook on the runner. The CI system is compromised from the PR check alone, before any merge or human review.",
		Severity:    model.SeverityCritical,
		RequiredFindingPatterns: []string{
			"CI-DEPBOT-001",
			"(SCM-PKG-003|DEP-004|RUGPULL-003)",
		},
	},
}

// RepoLevelCorrelationSpecs lists cross-directory patterns evaluated against the full finding set.
var RepoLevelCorrelationSpecs = []CorrelationSpec{
	DefaultCorrelationSpecs[3],
	DefaultCorrelationSpecs[4],
	DefaultCorrelationSpecs[5],
}

var compiledPatternCache sync.Map

// CachedRegexp returns a compiled regexp for pattern, caching the result for reuse across calls.
func CachedRegexp(pattern string) *regexp.Regexp {
	if re, ok := compiledPatternCache.Load(pattern); ok {
		return re.(*regexp.Regexp) //nolint:errcheck // sync.Map stores only *regexp.Regexp
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	compiledPatternCache.Store(pattern, re)
	return re
}

// RunCorrelation checks for multi-finding attack patterns grouped by directory scope.
func RunCorrelation(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return nil
	}

	dirGroups := GroupFindingsByDir(findings)
	var correlated []model.Finding

	for dir, dirFindings := range dirGroups {
		ruleIDs := ExtractRuleIDs(dirFindings)
		for _, spec := range DefaultCorrelationSpecs {
			if spec.ID == "COR-004" || spec.ID == "COR-005" || spec.ID == "COR-006" {
				continue
			}
			if MatchesAllPatterns(ruleIDs, spec.RequiredFindingPatterns) {
				refs := MatchingRuleIDs(ruleIDs, spec.RequiredFindingPatterns)
				f := model.Finding{
					RuleID:          spec.ID,
					ConfidenceClass: model.ConfidenceCorrelated,
					Title:           spec.Title,
					Description:     spec.Description,
					Category:        "correlation",
					Mitre:           "TA0001",
					Severity:        spec.Severity,
					File:            dir,
					Match:           fmt.Sprintf("correlated %d patterns across %d findings in %s", len(spec.RequiredFindingPatterns), len(dirFindings), dir),
					References:      refs,
				}
				patterns := spec.RequiredFindingPatterns
				if len(patterns) > 0 {
					matched := countMatchedPatterns(ruleIDs, patterns)
					f.Confidence = float64(matched) / float64(len(patterns))
				}
				correlated = append(correlated, f)
			}
		}
	}

	correlated = append(correlated, CorrelateByFileBasename(findings)...)
	correlated = append(correlated, ContentHashFindings(findings)...)
	correlated = append(correlated, RunRepoLevelCorrelation(findings, RepoLevelCorrelationSpecs)...)

	return correlated
}

// hasConfidenceDiversity checks that findings matching the spec's required patterns
// span at least two distinct ConfidenceClass values. Pure single-class echo (e.g.,
// all heuristic) should not be amplified through correlation.
func hasConfidenceDiversity(findings []model.Finding, patterns []string) bool {
	classes := make(map[model.ConfidenceClass]struct{})
	for _, pat := range patterns {
		re := CachedRegexp(pat)
		if re == nil {
			continue
		}
		for _, f := range findings {
			if re.MatchString(f.RuleID) {
				if f.ConfidenceClass != "" {
					classes[f.ConfidenceClass] = struct{}{}
				}
			}
		}
	}
	return len(classes) >= 2
}

// RunRepoLevelCorrelation checks correlation specs against all findings in the repo,
// not scoped to individual directories. This catches cross-directory attack chains.
func RunRepoLevelCorrelation(findings []model.Finding, specs []CorrelationSpec) []model.Finding {
	if len(findings) == 0 || len(specs) == 0 {
		return nil
	}
	ruleIDs := ExtractRuleIDs(findings)
	var correlated []model.Finding
	skipDiversityCheck := map[string]bool{
		"COR-006": true,
	}
	for _, spec := range specs {
		if !MatchesAllPatterns(ruleIDs, spec.RequiredFindingPatterns) {
			continue
		}
		if !skipDiversityCheck[spec.ID] && !hasConfidenceDiversity(findings, spec.RequiredFindingPatterns) {
			continue
		}
		refs := MatchingRuleIDs(ruleIDs, spec.RequiredFindingPatterns)
		f := model.Finding{
			RuleID:          spec.ID,
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           spec.Title,
			Description:     spec.Description,
			Category:        "correlation",
			Mitre:           "TA0001",
			Severity:        spec.Severity,
			File:            "(repo)",
			Match:           fmt.Sprintf("correlated %d patterns across %d findings (repo-wide)", len(spec.RequiredFindingPatterns), len(findings)),
			References:      refs,
		}
		patterns := spec.RequiredFindingPatterns
		if len(patterns) > 0 {
			matched := countMatchedPatterns(ruleIDs, patterns)
			f.Confidence = float64(matched) / float64(len(patterns))
		}
		correlated = append(correlated, f)
	}
	return correlated
}

// matchContentHashPrefix returns the first 16 hex characters of the SHA-256 digest of the match text.
func matchContentHashPrefix(match string) string {
	sum := sha256.Sum256([]byte(match))
	return hex.EncodeToString(sum[:])[:16]
}

// ContentHashFindings groups findings by match content hash for cross-file payload correlation.
// When the same match payload appears in four or more distinct files, emits COR-PAYLOAD-001.
func ContentHashFindings(findings []model.Finding) []model.Finding {
	type hashGroup struct {
		files    map[string]struct{}
		findings []model.Finding
	}
	byHash := make(map[string]*hashGroup)
	for _, f := range findings {
		if f.Match == "" {
			continue
		}
		h := matchContentHashPrefix(f.Match)
		g := byHash[h]
		if g == nil {
			g = &hashGroup{files: make(map[string]struct{})}
			byHash[h] = g
		}
		if f.File != "" {
			g.files[f.File] = struct{}{}
		}
		g.findings = append(g.findings, f)
	}
	var out []model.Finding
	for hashPrefix, g := range byHash {
		if len(g.files) < 4 {
			continue
		}
		ruleIDs := ExtractRuleIDs(g.findings)
		out = append(out, model.Finding{
			RuleID:          "COR-PAYLOAD-001",
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           "Identical match payload across multiple files",
			Description:     fmt.Sprintf("The same matched content (hash prefix %s) appears in %d distinct files, suggesting coordinated or copied malicious payloads.", hashPrefix, len(g.files)),
			Category:        "correlation",
			Mitre:           "TA0001",
			Severity:        model.SeverityHigh,
			File:            "(correlation)",
			Match:           fmt.Sprintf("content_hash_prefix=%s files=%d", hashPrefix, len(g.files)),
			References:      ruleIDs,
		})
	}
	return out
}

// CorrelateByFileBasename emits COR-FILE-001 when many distinct rule families hit the same file basename.
func CorrelateByFileBasename(findings []model.Finding) []model.Finding {
	byBase := make(map[string][]model.Finding)
	for _, f := range findings {
		base := filepath.Base(f.File)
		if base == "" || base == "." {
			continue
		}
		byBase[base] = append(byBase[base], f)
	}
	var out []model.Finding
	for base, group := range byBase {
		if len(group) < 3 {
			continue
		}
		families := make(map[string]struct{})
		for _, f := range group {
			fam := RuleFamilyPrefix(f.RuleID)
			if fam != "" {
				families[fam] = struct{}{}
			}
		}
		if len(families) < 4 {
			continue
		}
		classes := make(map[model.ConfidenceClass]struct{})
		for _, f := range group {
			if f.ConfidenceClass != "" {
				classes[f.ConfidenceClass] = struct{}{}
			}
		}
		if len(classes) < 2 {
			continue
		}
		ruleIDs := ExtractRuleIDs(group)
		out = append(out, model.Finding{
			RuleID:          "COR-FILE-001",
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           "Multiple rule families target the same file basename",
			Description:     fmt.Sprintf("%d distinct rule families reported findings for files named %q, suggesting concentrated risk on that workflow or config surface.", len(families), base),
			Category:        "correlation",
			Mitre:           "TA0001",
			Severity:        model.SeverityHigh,
			File:            base,
			Match:           fmt.Sprintf("basename=%s families=%d findings=%d", base, len(families), len(group)),
			References:      ruleIDs,
		})
	}
	return out
}

// RuleFamilyPrefix strips the trailing numeric suffix from a rule ID to produce its family prefix (e.g. "CI-PRT-001" -> "CI-PRT").
func RuleFamilyPrefix(ruleID string) string {
	ruleID = strings.TrimSpace(ruleID)
	if ruleID == "" {
		return ""
	}
	i := strings.LastIndex(ruleID, "-")
	if i <= 0 {
		return ruleID
	}
	suffix := ruleID[i+1:]
	if suffix == "" {
		return ruleID
	}
	allDigit := true
	for _, r := range suffix {
		if !unicode.IsDigit(r) {
			allDigit = false
			break
		}
	}
	if allDigit {
		return ruleID[:i]
	}
	return ruleID
}

// GroupFindingsByDir partitions findings by the directory of their source file.
func GroupFindingsByDir(findings []model.Finding) map[string][]model.Finding {
	groups := make(map[string][]model.Finding)
	for _, f := range findings {
		dir := filepath.Dir(f.File)
		if dir == "" || dir == "." {
			dir = "(root)"
		}
		groups[dir] = append(groups[dir], f)
	}
	return groups
}

// ExtractRuleIDs returns the unique rule IDs from findings in encounter order.
func ExtractRuleIDs(findings []model.Finding) []string {
	ids := make([]string, 0, len(findings))
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		if _, ok := seen[f.RuleID]; ok {
			continue
		}
		seen[f.RuleID] = struct{}{}
		ids = append(ids, f.RuleID)
	}
	return ids
}

// countMatchedPatterns returns how many entries in patterns have a compiled regexp
// that matches at least one rule ID.
func countMatchedPatterns(ruleIDs []string, patterns []string) int {
	n := 0
	for _, pat := range patterns {
		re := CachedRegexp(pat)
		if re == nil {
			continue
		}
		for _, id := range ruleIDs {
			if re.MatchString(id) {
				n++
				break
			}
		}
	}
	return n
}

// MatchesAllPatterns reports whether every pattern in patterns matches at least one of the given ruleIDs.
func MatchesAllPatterns(ruleIDs []string, patterns []string) bool {
	for _, pat := range patterns {
		re := CachedRegexp(pat)
		if re == nil {
			continue
		}
		matched := false
		for _, id := range ruleIDs {
			if re.MatchString(id) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// MatchingRuleIDs returns the subset of ruleIDs that match any of the given patterns.
func MatchingRuleIDs(ruleIDs []string, patterns []string) []string {
	var refs []string
	seen := make(map[string]struct{})
	for _, pat := range patterns {
		re := CachedRegexp(pat)
		if re == nil {
			continue
		}
		for _, id := range ruleIDs {
			if re.MatchString(id) {
				if _, ok := seen[id]; !ok {
					refs = append(refs, id)
					seen[id] = struct{}{}
				}
			}
		}
	}
	return refs
}

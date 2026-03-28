package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
)

// BehaviorProfileVersion is the JSON schema version for serialized BehaviorProfile values.
const BehaviorProfileVersion = 1

// DriftConfig holds settings for drift comparison between behavior profiles, including
// severity-shift sensitivity and allowlisted new behavior chain patterns.
type DriftConfig struct {
	SeverityShiftMultiplier float64
	AllowedNewChains        []string
	ProfileVersion          int
}

// DefaultDriftConfig returns drift settings with library defaults.
func DefaultDriftConfig() DriftConfig {
	return DriftConfig{
		SeverityShiftMultiplier: 2.0,
		AllowedNewChains:        nil,
		ProfileVersion:          BehaviorProfileVersion,
	}
}

// BehaviorProfile summarizes scan findings as behavior chain IDs, policy check IDs,
// severity distribution, optional per-severity rates per 1K files, and a short profile hash.
type BehaviorProfile struct {
	Version          int                `json:"version"`
	BehaviorChainIDs []string           `json:"behavior_chain_ids"`
	PolicyCheckIDs   []string           `json:"policy_check_ids"`
	SeverityDist     map[string]int     `json:"severity_distribution"`
	TotalFindings    int                `json:"total_findings"`
	ScannedFiles     int                `json:"scanned_files,omitempty"`
	NormalizedCounts map[string]float64 `json:"normalized_counts,omitempty"`
	ProfileHash      string             `json:"profile_hash"`
}

// DefaultProfileHistoryMax is the default cap on stored profiles for trend analysis.
const DefaultProfileHistoryMax = 5

// ProfileHistory tracks recent behavior profiles for trend analysis.
type ProfileHistory struct {
	MaxProfiles int
	Profiles    []BehaviorProfile
}

// Push adds a new profile, evicting the oldest if at capacity.
func (h *ProfileHistory) Push(p BehaviorProfile) {
	if h.MaxProfiles <= 0 {
		h.MaxProfiles = DefaultProfileHistoryMax
	}
	h.Profiles = append(h.Profiles, p)
	if len(h.Profiles) > h.MaxProfiles {
		excess := len(h.Profiles) - h.MaxProfiles
		h.Profiles = h.Profiles[excess:]
	}
}

// Len returns the current number of stored profiles.
func (h *ProfileHistory) Len() int {
	return len(h.Profiles)
}

// normalizedSeverityPer1K returns per-1K-files normalized count for a severity label.
func normalizedSeverityPer1K(p BehaviorProfile, severity string) float64 {
	count := 0
	if p.SeverityDist != nil {
		count = p.SeverityDist[severity]
	}
	if p.ScannedFiles > 0 {
		return float64(count) * 1000.0 / float64(p.ScannedFiles)
	}
	if p.NormalizedCounts != nil {
		if v, ok := p.NormalizedCounts[severity]; ok {
			return v
		}
	}
	return 0
}

func severityMonotonicStrictIncreasing(vals []float64) bool {
	if len(vals) < 2 {
		return false
	}
	for i := 0; i < len(vals)-1; i++ {
		if vals[i] >= vals[i+1] {
			return false
		}
	}
	return true
}

// ComputeTrend analyzes monotonic severity trends across 3+ profiles.
// Returns findings when normalized severity counts are strictly increasing over consecutive profiles
// for any severity level of medium or higher.
func (h *ProfileHistory) ComputeTrend() []model.Finding {
	if len(h.Profiles) < 3 {
		return nil
	}
	var out []model.Finding
	// Order: critical, high, medium (all >= medium)
	for _, sev := range []string{"critical", "high", "medium"} {
		vals := make([]float64, len(h.Profiles))
		for i := range h.Profiles {
			vals[i] = normalizedSeverityPer1K(h.Profiles[i], sev)
		}
		if !severityMonotonicStrictIncreasing(vals) {
			continue
		}
		out = append(out, model.Finding{
			RuleID:          "DRIFT-TREND-001",
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           "Monotonic severity drift trend",
			Description:     fmt.Sprintf("Normalized %s-severity findings per 1K scanned files increased on each of the last %d profile snapshots (worsening trend).", sev, len(h.Profiles)),
			Category:        "drift-detection",
			Mitre:           "TA0040",
			Severity:        model.SeverityHigh,
			File:            "(drift-trend)",
			Match:           fmt.Sprintf("severity=%s normalized_per_1k=%v", sev, vals),
		})
	}
	return out
}

// LoadProfileHistory reads profile history from a JSON file.
func LoadProfileHistory(path string) (ProfileHistory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ProfileHistory{}, err
	}
	var h ProfileHistory
	if err := json.Unmarshal(data, &h); err != nil {
		return ProfileHistory{}, err
	}
	if h.MaxProfiles < 0 {
		return ProfileHistory{}, fmt.Errorf("invalid MaxProfiles %d", h.MaxProfiles)
	}
	for _, p := range h.Profiles {
		if p.Version > BehaviorProfileVersion {
			return ProfileHistory{}, fmt.Errorf("unsupported behavior profile version %d (max %d)", p.Version, BehaviorProfileVersion)
		}
	}
	return h, nil
}

// SaveProfileHistory writes profile history to a JSON file.
func SaveProfileHistory(path string, h ProfileHistory) error {
	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// DriftReport describes differences between two behavior profiles: new or disappeared
// behavior chains and policy checks, and whether severity counts crossed a shift threshold.
type DriftReport struct {
	NewChains           []string `json:"new_chains,omitempty"`
	DisappearedChains   []string `json:"disappeared_chains,omitempty"`
	NewPolicies         []string `json:"new_policies,omitempty"`
	DisappearedPolicies []string `json:"disappeared_policies,omitempty"`
	SeverityShift       bool     `json:"severity_shift"`
	ShiftDetail         string   `json:"shift_detail,omitempty"`
}

// BuildBehaviorProfile computes a BehaviorProfile summarizing severity distribution, behavior chains, and policy findings.
func BuildBehaviorProfile(findings []model.Finding, totalFiles int) BehaviorProfile {
	chainSet := make(map[string]struct{})
	policySet := make(map[string]struct{})
	sevDist := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "BHV-") {
			chainSet[f.RuleID] = struct{}{}
		}
		if strings.HasPrefix(f.RuleID, "POL-") || strings.HasPrefix(f.RuleID, "SCM-") {
			policySet[f.RuleID] = struct{}{}
		}
		sevDist[string(f.Severity)]++
	}
	chains := model.SortedMapKeys(chainSet)
	policies := model.SortedMapKeys(policySet)

	sevParts := sortedSeverityDistParts(sevDist)
	sevStr := strings.Join(sevParts, ",")
	raw := strings.Join(chains, ",") + "|" + strings.Join(policies, ",") + "|" + sevStr
	h := sha256.Sum256([]byte(raw))

	norm := make(map[string]float64)
	if totalFiles > 0 {
		for sev, count := range sevDist {
			norm[sev] = (float64(count) / float64(totalFiles)) * 1000.0
		}
	}

	return BehaviorProfile{
		Version:          BehaviorProfileVersion,
		BehaviorChainIDs: chains,
		PolicyCheckIDs:   policies,
		SeverityDist:     sevDist,
		TotalFindings:    len(findings),
		ScannedFiles:     totalFiles,
		NormalizedCounts: norm,
		ProfileHash:      hex.EncodeToString(h[:8]),
	}
}

func sortedSeverityDistParts(dist map[string]int) []string {
	keys := make([]string, 0, len(dist))
	for k := range dist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, dist[k]))
	}
	return parts
}

// ComputeDrift compares current and previous profiles and returns a DriftReport using cfg.
func ComputeDrift(current, previous BehaviorProfile, cfg DriftConfig) DriftReport {
	mult := cfg.SeverityShiftMultiplier
	if mult <= 0 {
		mult = DefaultDriftConfig().SeverityShiftMultiplier
	}

	prevChains := setFromSlice(previous.BehaviorChainIDs)
	currChains := setFromSlice(current.BehaviorChainIDs)

	var newChains, disappeared []string
	for c := range currChains {
		if _, ok := prevChains[c]; !ok {
			newChains = append(newChains, c)
		}
	}
	for c := range prevChains {
		if _, ok := currChains[c]; !ok {
			disappeared = append(disappeared, c)
		}
	}
	sort.Strings(newChains)
	sort.Strings(disappeared)

	newChains = filterOutAllowedNewChains(newChains, cfg.AllowedNewChains)

	prevPolicies := setFromSlice(previous.PolicyCheckIDs)
	currPolicies := setFromSlice(current.PolicyCheckIDs)
	var newPolicies, disappearedPolicies []string
	for p := range currPolicies {
		if _, ok := prevPolicies[p]; !ok {
			newPolicies = append(newPolicies, p)
		}
	}
	for p := range prevPolicies {
		if _, ok := currPolicies[p]; !ok {
			disappearedPolicies = append(disappearedPolicies, p)
		}
	}
	sort.Strings(newPolicies)
	sort.Strings(disappearedPolicies)

	shift := false
	detail := ""
	for sev, count := range current.SeverityDist {
		prev := previous.SeverityDist[sev]
		if prev > 0 && float64(count) > float64(prev)*mult {
			shift = true
			detail = fmt.Sprintf("%s: %d -> %d", sev, prev, count)
			break
		}
	}

	return DriftReport{
		NewChains:           newChains,
		DisappearedChains:   disappeared,
		NewPolicies:         newPolicies,
		DisappearedPolicies: disappearedPolicies,
		SeverityShift:       shift,
		ShiftDetail:         detail,
	}
}

func filterOutAllowedNewChains(chains []string, patterns []string) []string {
	if len(patterns) == 0 {
		return chains
	}
	var out []string
	for _, c := range chains {
		if chainMatchesAnyPattern(c, patterns) {
			continue
		}
		out = append(out, c)
	}
	return out
}

func chainMatchesAnyPattern(chain string, patterns []string) bool {
	for _, p := range patterns {
		if matched, err := path.Match(p, chain); err == nil && matched {
			return true
		}
	}
	return false
}

// DriftToFindings converts a DriftReport into DRIFT-prefixed findings for new chains, disappeared chains, and severity shifts.
func DriftToFindings(dr DriftReport) []model.Finding {
	var findings []model.Finding
	for _, chain := range dr.NewChains {
		findings = append(findings, model.Finding{
			RuleID:          "DRIFT-001",
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           "New behavior chain detected",
			Description:     fmt.Sprintf("Behavior chain %s appeared since last baseline.", chain),
			Category:        "drift-detection",
			Mitre:           "TA0001",
			Severity:        model.SeverityMedium,
			File:            "(drift)",
			Match:           chain,
		})
	}
	for _, chain := range dr.DisappearedChains {
		findings = append(findings, model.Finding{
			RuleID:          "DRIFT-002",
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           "Behavior chain disappeared",
			Description:     fmt.Sprintf("Behavior chain %s no longer present.", chain),
			Category:        "drift-detection",
			Mitre:           "TA0005",
			Severity:        model.SeverityInfo,
			File:            "(drift)",
			Match:           chain,
		})
	}
	if dr.SeverityShift {
		findings = append(findings, model.Finding{
			RuleID:          "DRIFT-003",
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           "Severity distribution shift",
			Description:     fmt.Sprintf("Significant severity change: %s", dr.ShiftDetail),
			Category:        "drift-detection",
			Mitre:           "TA0040",
			Severity:        model.SeverityHigh,
			File:            "(drift)",
			Match:           dr.ShiftDetail,
		})
	}
	for _, pol := range dr.NewPolicies {
		findings = append(findings, model.Finding{
			RuleID:          "DRIFT-004",
			ConfidenceClass: model.ConfidenceCorrelated,
			Title:           "New policy violation detected",
			Description:     fmt.Sprintf("Policy check %s appeared since last baseline.", pol),
			Category:        "drift-detection",
			Mitre:           "TA0001",
			Severity:        model.SeverityMedium,
			File:            "(drift)",
			Match:           pol,
		})
	}
	return findings
}

// SaveBehaviorProfile writes profile to path as indented JSON.
func SaveBehaviorProfile(path string, profile BehaviorProfile) error {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadBehaviorProfile reads and validates a behavior profile from path.
func LoadBehaviorProfile(path string) (BehaviorProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BehaviorProfile{}, err
	}
	var profile BehaviorProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return BehaviorProfile{}, err
	}
	if profile.Version > BehaviorProfileVersion {
		return BehaviorProfile{}, fmt.Errorf("unsupported behavior profile version %d (max %d)", profile.Version, BehaviorProfileVersion)
	}
	return profile, nil
}

func setFromSlice(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

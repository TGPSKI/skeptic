package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// BuildRuleSet merges default and external rules with integrity/signature/quality enforcement.
// When includeDefaults is true, defaultRules is prepended; callers should pass the built-in rule slice (e.g. DefaultRules()).
//
//nolint:gocyclo // multi-source rule loading with integrity gates
func BuildRuleSet(
	includeDefaults bool,
	defaultRules []Rule,
	rulesFileArg string,
	rulesDir string,
	rulesSHA256Arg string,
	rulesPubKeyArg string,
	requireSignedRules bool,
	ruleQualityMode model.RuleQualityMode,
	logger *logging.Logger,
) ([]Rule, error) {
	all := make([]Rule, 0, 256)
	if includeDefaults {
		all = append(all, defaultRules...)
	}

	rulesHashByPath, err := BuildRuleHashMap(rulesFileArg, rulesSHA256Arg)
	if err != nil {
		return nil, err
	}
	publicKeys, err := LoadPublicKeys(SplitCSV(rulesPubKeyArg))
	if err != nil {
		return nil, fmt.Errorf("load rules public keys: %w", err)
	}
	if requireSignedRules && len(publicKeys) == 0 {
		return nil, errors.New("--require-signed-rules needs --rules-pubkey with one or more Ed25519 public key PEM paths")
	}

	externalFiles, err := CollectRuleFiles(rulesFileArg, rulesDir)
	if err != nil {
		return nil, err
	}
	if logger != nil {
		logger.Infof("loading %d external rule files", len(externalFiles))
		if len(externalFiles) > 0 && len(rulesHashByPath) == 0 && len(publicKeys) == 0 {
			logger.Warnf(
				"external rules are loaded without integrity enforcement; prefer --rules-sha256 and/or --rules-pubkey",
			)
		}
		if len(externalFiles) > 0 && len(publicKeys) > 0 && !requireSignedRules {
			logger.Warnf(
				"public keys are configured but --require-signed-rules is disabled; unsigned rule packs may still load",
			)
		}
	}
	for _, file := range externalFiles {
		if len(publicKeys) > 0 || requireSignedRules {
			sigPath := DefaultRulepackSignaturePath(file)
			signature, err := LoadRulepackSignature(sigPath)
			if err != nil {
				if os.IsNotExist(err) {
					if requireSignedRules {
						return nil, fmt.Errorf("missing detached signature for %s (expected %s)", file, sigPath)
					}
					if logger != nil && len(publicKeys) > 0 {
						logger.Warnf("rules signature missing for %s (expected %s); skipping signature verification", file, sigPath)
					}
				} else {
					return nil, fmt.Errorf("load detached signature for %s: %w", file, err)
				}
			} else {
				if len(publicKeys) == 0 {
					return nil, fmt.Errorf("signature found for %s but no --rules-pubkey provided", file)
				}
				if err := VerifyRulepackFileSignature(file, signature, publicKeys); err != nil {
					return nil, fmt.Errorf("verify detached signature for %s: %w", file, err)
				}
				if logger != nil {
					logger.Debugf("verified signature for rules file: %s", file)
				}
			}
		}
		if expected, ok := rulesHashByPath[file]; ok {
			actual, err := security.SHA256FileHex(file)
			if err != nil {
				return nil, fmt.Errorf("compute sha256 for %s: %w", file, err)
			}
			if actual != expected {
				return nil, fmt.Errorf("sha256 mismatch for %s: expected %s got %s", file, expected, actual)
			}
			if logger != nil {
				logger.Debugf("verified sha256 for rules file: %s", file)
			}
		}
		loaded, err := LoadRulesFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("load rules from %s: %w", file, err)
		}
		specs := make([]model.RuleSpec, 0, len(loaded))
		for _, rule := range loaded {
			specs = append(specs, model.RuleSpec{
				ID:          rule.ID,
				Title:       rule.Title,
				Description: rule.Description,
				Category:    rule.Category,
				Mitre:       rule.Mitre,
				Severity:    rule.Severity,
				Pattern:     rule.Pattern,
				Target:      rule.Target,
			})
		}
		if err := EnforceRuleQualityForSpecs(specs, file, ruleQualityMode, logger); err != nil {
			return nil, err
		}
		all = append(all, loaded...)
	}

	return DedupeRules(all), nil
}

// FilterRules applies include and exclude ID patterns to a rules slice.
// If include is non-empty, only rules matching at least one include pattern are kept.
// Rules matching any exclude pattern are then removed.
// Matching is exact ID equality, filepath.Match glob (e.g. "BHV-*-001"), or prefix
// when the pattern contains no glob metacharacters (e.g. "BHV-" matches "BHV-ORD-001").
func FilterRules(rules []Rule, include, exclude []string) []Rule {
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if len(include) > 0 {
			ok := false
			for _, p := range include {
				if RuleIDMatchesPattern(rule.ID, p) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		excluded := false
		for _, p := range exclude {
			if RuleIDMatchesPattern(rule.ID, p) {
				excluded = true
				break
			}
		}
		if excluded {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// RuleIDMatchesPattern reports whether id matches pattern using the same rules as
// --include-rules / --exclude-rules: exact match, filepath.Match glob, or prefix
// match when pattern has no glob metacharacters.
func RuleIDMatchesPattern(id, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if id == pattern {
		return true
	}
	if matched, err := filepath.Match(pattern, id); err == nil && matched {
		return true
	}
	if !strings.ContainsAny(pattern, `*?[]`) && strings.HasPrefix(id, pattern) {
		return true
	}
	return false
}

// BuildRuleHashMap pairs --rules-file entries with expected SHA256 hashes.
func BuildRuleHashMap(rulesFileArg string, rulesSHA256Arg string) (map[string]string, error) {
	hashes := SplitCSV(rulesSHA256Arg)
	if len(hashes) == 0 {
		return map[string]string{}, nil
	}

	filesArg := SplitCSV(rulesFileArg)
	if len(filesArg) == 0 {
		return nil, errors.New("--rules-sha256 requires --rules-file entries")
	}
	if len(filesArg) != len(hashes) {
		return nil, fmt.Errorf("--rules-file count (%d) must match --rules-sha256 count (%d)", len(filesArg), len(hashes))
	}

	out := make(map[string]string, len(filesArg))
	for i, fileRaw := range filesArg {
		path := model.ExpandHomePath(fileRaw)
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		normalizedHash, err := security.NormalizeSHA256(hashes[i])
		if err != nil {
			return nil, fmt.Errorf("invalid sha256 for %s: %w", fileRaw, err)
		}
		out[abs] = normalizedHash
	}
	return out, nil
}

// CollectRuleFiles resolves and de-duplicates rule files from flags/directories.
func CollectRuleFiles(rulesFileArg string, rulesDir string) ([]string, error) {
	out := make([]string, 0, 8)
	seen := make(map[string]struct{}, 8)

	for _, raw := range SplitCSV(rulesFileArg) {
		if raw == "" {
			continue
		}
		path := model.ExpandHomePath(raw)
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[abs]; exists {
			continue
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}

	if strings.TrimSpace(rulesDir) != "" {
		dir := model.ExpandHomePath(strings.TrimSpace(rulesDir))
		absDir, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		err = filepath.WalkDir(absDir, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			name := strings.ToLower(d.Name())
			if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.sig") {
				return nil
			}
			if strings.Contains(name, ".test.") {
				return nil
			}
			if _, exists := seen[path]; exists {
				return nil
			}
			seen[path] = struct{}{}
			out = append(out, path)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	slices.Sort(out)
	return out, nil
}

// LoadRulesFromFile supports both RulePack and []RuleSpec JSON formats.
func LoadRulesFromFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// First try the rule pack format.
	var pack model.RulePack
	if err := json.Unmarshal(data, &pack); err == nil && len(pack.Rules) > 0 {
		return CompileRuleSpecs(pack.Rules, path)
	}

	// Then allow a bare list of rules.
	var bare []model.RuleSpec
	if err := json.Unmarshal(data, &bare); err == nil && len(bare) > 0 {
		return CompileRuleSpecs(bare, path)
	}

	return nil, errors.New("unsupported rule file format; expected RulePack or []RuleSpec JSON")
}

// CompileRuleSpecs validates and compiles regex patterns for loaded rule specs.
func CompileRuleSpecs(specs []model.RuleSpec, path string) ([]Rule, error) {
	out := make([]Rule, 0, len(specs))
	for i, spec := range specs {
		if strings.TrimSpace(spec.ID) == "" {
			return nil, fmt.Errorf("%s: rules[%d] missing id", path, i)
		}
		if strings.TrimSpace(spec.Pattern) == "" {
			return nil, fmt.Errorf("%s: rules[%d] missing pattern", path, i)
		}
		if strings.TrimSpace(string(spec.Severity)) == "" {
			return nil, fmt.Errorf("%s: rules[%d] missing severity", path, i)
		}
		if _, err := model.ParseSeverity(string(spec.Severity)); err != nil {
			return nil, fmt.Errorf("%s: rules[%d] invalid severity: %w", path, i, err)
		}
		if spec.Target != TargetContent && spec.Target != TargetPath {
			return nil, fmt.Errorf("%s: rules[%d] target must be content or path", path, i)
		}
		re, err := regexp.Compile(spec.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: rules[%d] invalid regex: %w", path, i, err)
		}
		out = append(out, Rule{
			ID:          spec.ID,
			Title:       spec.Title,
			Description: spec.Description,
			Category:    spec.Category,
			Mitre:       spec.Mitre,
			Severity:    spec.Severity,
			Pattern:     spec.Pattern,
			Target:      spec.Target,
			RE:          re,
			LiteralHint: ExtractLiteralHint(spec.Pattern),
		})
	}
	return out, nil
}

// DedupeRules removes duplicate rule definitions while preserving stable order.
func DedupeRules(in []Rule) []Rule {
	out := make([]Rule, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, rule := range in {
		key := fmt.Sprintf("%s|%s|%s|%s", rule.ID, rule.Target, rule.Pattern, rule.Severity)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rule)
	}
	return out
}

// ExtractLiteralHint finds the longest case-insensitive literal substring that must be
// present for the regex pattern to match. Returns "" if no reliable literal can be extracted.
// Only top-level literals are considered; content inside parenthesized groups is skipped
// because groups may contain alternations where only one branch needs to match.
//
//nolint:gocyclo // regex character-class parser requires per-char branching
func ExtractLiteralHint(pattern string) string {
	p := pattern
	for strings.HasPrefix(p, "(?") {
		end := strings.Index(p, ")")
		if end < 0 {
			break
		}
		p = p[end+1:]
	}

	var best string
	var cur strings.Builder
	i := 0
	depth := 0
	flush := func() {
		s := cur.String()
		if len(s) > len(best) {
			best = s
		}
		cur.Reset()
	}
	for i < len(p) {
		ch := p[i]
		if ch == '(' {
			flush()
			depth++
			i++
			continue
		}
		if ch == ')' {
			if depth > 0 {
				depth--
			}
			i++
			continue
		}
		if depth > 0 {
			i++
			continue
		}
		switch {
		case ch == '\\' && i+1 < len(p):
			next := p[i+1]
			if next == '.' || next == '*' || next == '+' || next == '?' ||
				next == '(' || next == ')' || next == '[' || next == ']' ||
				next == '{' || next == '}' || next == '|' || next == '^' ||
				next == '$' || next == '\\' || next == '/' {
				cur.WriteByte(next)
				i += 2
			} else {
				flush()
				i += 2
			}
		case ch == '.' || ch == '*' || ch == '+' || ch == '?' ||
			ch == '[' || ch == '{' || ch == '|' || ch == '^' || ch == '$':
			flush()
			if ch == '[' {
				for i < len(p) && p[i] != ']' {
					i++
				}
			}
			if ch == '{' {
				for i < len(p) && p[i] != '}' {
					i++
				}
			}
			i++
		default:
			cur.WriteByte(ch)
			i++
		}
	}
	flush()
	if len(best) < 3 {
		return ""
	}
	return strings.ToLower(best)
}

// ApplyLiteralHints populates LiteralHint on each rule from its Pattern.
func ApplyLiteralHints(rules []Rule) {
	for i := range rules {
		if rules[i].LiteralHint != "" {
			continue
		}
		h := ExtractLiteralHint(rules[i].Pattern)
		if h == "" {
			h = fallbackLiteralHints[rules[i].ID]
		}
		rules[i].LiteralHint = h
	}
}

// SplitCSV parses comma-separated CLI lists while trimming empty entries.
func SplitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return out
}

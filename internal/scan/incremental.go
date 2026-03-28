package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// ScanStateVersion is the current on-disk incremental cache schema version.
const ScanStateVersion = 1

// ScanState is the serialized cache file format for incremental scans.
type ScanState struct {
	Version      int                        `json:"version"`
	RulesetHash  string                     `json:"ruleset_hash"`
	UpdatedAt    string                     `json:"updated_at"`
	EntriesByAbs map[string]ScanStateRecord `json:"entries_by_abs"`
}

// ScanStateRecord stores file identity and content metadata between runs.
type ScanStateRecord struct {
	Size          int64  `json:"size"`
	ModUnixNano   int64  `json:"mod_unix_nano"`
	SHA256        string `json:"sha256,omitempty"`
	LastScannedAt string `json:"last_scanned_at,omitempty"`
}

// IncrementalStateCache tracks scan eligibility and cache persistence for changed-file mode.
type IncrementalStateCache struct {
	enabled      bool
	path         string
	state        ScanState
	seen         map[string]struct{}
	skipEnabled  bool
	rulesChanged bool
	logger       model.ScanLogger
}

// NewIncrementalStateCache initializes cache state and handles version/ruleset invalidation.
func NewIncrementalStateCache(path string, rulesetHash string, enabled bool, logger model.ScanLogger) (*IncrementalStateCache, error) {
	cache := &IncrementalStateCache{
		enabled: enabled,
		path:    "",
		state: ScanState{
			Version:      ScanStateVersion,
			RulesetHash:  strings.TrimSpace(rulesetHash),
			EntriesByAbs: make(map[string]ScanStateRecord, 1024),
		},
		seen:        make(map[string]struct{}, 1024),
		skipEnabled: enabled,
		logger:      logger,
	}
	if !enabled {
		return cache, nil
	}
	absPath, err := filepath.Abs(model.ExpandHomePath(path))
	if err != nil {
		return nil, err
	}
	cache.path = absPath
	if err := cache.load(); err != nil {
		return nil, err
	}

	if cache.state.Version != ScanStateVersion {
		if cache.logger != nil {
			cache.logger.Warnf("state cache version mismatch, forcing full scan: have=%d want=%d", cache.state.Version, ScanStateVersion)
		}
		cache.state = ScanState{
			Version:      ScanStateVersion,
			RulesetHash:  strings.TrimSpace(rulesetHash),
			EntriesByAbs: make(map[string]ScanStateRecord, 1024),
		}
		cache.rulesChanged = true
		cache.skipEnabled = false
		return cache, nil
	}

	if strings.TrimSpace(cache.state.RulesetHash) != strings.TrimSpace(rulesetHash) {
		cache.rulesChanged = true
		cache.skipEnabled = false
		if cache.logger != nil {
			cache.logger.Warnf("ruleset changed since previous incremental run; performing full scan and refreshing cache")
		}
	}
	return cache, nil
}

// Enabled reports whether incremental behavior is active for this run.
func (c *IncrementalStateCache) Enabled() bool {
	return c != nil && c.enabled
}

// Path returns canonical cache file location.
func (c *IncrementalStateCache) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// RulesChanged reports whether the current ruleset invalidated skip decisions.
func (c *IncrementalStateCache) RulesChanged() bool {
	if c == nil {
		return false
	}
	return c.rulesChanged
}

// ShouldScan decides whether a regular file requires scanning this run.
func (c *IncrementalStateCache) ShouldScan(absPath string, info os.FileInfo) (bool, error) {
	if c == nil || !c.enabled {
		return true, nil
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	absPath = filepath.Clean(absPath)
	c.seen[absPath] = struct{}{}

	if !c.skipEnabled {
		return true, nil
	}
	record, ok := c.state.EntriesByAbs[absPath]
	if !ok {
		return true, nil
	}

	size := info.Size()
	mod := info.ModTime().UnixNano()
	if record.Size == size && record.ModUnixNano == mod {
		return false, nil
	}
	if record.Size != size {
		return true, nil
	}
	if strings.TrimSpace(record.SHA256) == "" {
		return true, nil
	}

	// mtime changed but size is stable: hash to avoid rescanning untouched content.
	currentHash, err := security.SHA256FileHex(absPath)
	if err != nil {
		return true, nil
	}
	if currentHash == record.SHA256 {
		record.ModUnixNano = mod
		c.state.EntriesByAbs[absPath] = record
		return false, nil
	}
	return true, nil
}

// Record updates cache metadata for a scanned file.
func (c *IncrementalStateCache) Record(absPath string, info os.FileInfo, sha string) {
	if c == nil || !c.enabled {
		return
	}
	absPath = filepath.Clean(absPath)
	record := ScanStateRecord{
		Size:          info.Size(),
		ModUnixNano:   info.ModTime().UnixNano(),
		LastScannedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if normalized, err := security.NormalizeSHA256(sha); err == nil {
		record.SHA256 = normalized
	}
	c.state.EntriesByAbs[absPath] = record
	c.seen[absPath] = struct{}{}
}

// Finalize updates global cache metadata and prunes stale entries after full traversal.
func (c *IncrementalStateCache) Finalize(completeTraversal bool, rulesetHash string) {
	if c == nil || !c.enabled {
		return
	}
	c.state.RulesetHash = strings.TrimSpace(rulesetHash)
	c.state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	c.state.Version = ScanStateVersion

	if !completeTraversal {
		return
	}

	for path := range c.state.EntriesByAbs {
		if _, ok := c.seen[path]; ok {
			continue
		}
		delete(c.state.EntriesByAbs, path)
	}
}

// Save writes cache state atomically at the end of a run.
func (c *IncrementalStateCache) Save() error {
	if c == nil || !c.enabled {
		return nil
	}
	if strings.TrimSpace(c.path) == "" {
		return errors.New("incremental state cache path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c.state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(c.path, data, 0o644)
}

// load hydrates cache state from disk when present.
func (c *IncrementalStateCache) load() error {
	data, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var loaded ScanState
	if err := json.Unmarshal(data, &loaded); err != nil {
		if c.logger != nil {
			c.logger.Warnf("incremental state cache unreadable, starting without cache: %v", err)
		}
		return nil
	}
	if loaded.EntriesByAbs == nil {
		loaded.EntriesByAbs = make(map[string]ScanStateRecord, 1024)
	}
	c.state = loaded
	return nil
}

// ComputeRulesetHash creates deterministic cache invalidation identity for active rules.
func ComputeRulesetHash(rules []model.Rule) string {
	canonical := make([]string, 0, len(rules))
	for _, rule := range rules {
		canonical = append(canonical, strings.Join([]string{
			strings.TrimSpace(rule.ID),
			strings.TrimSpace(rule.Title),
			strings.TrimSpace(rule.Category),
			strings.TrimSpace(rule.Mitre),
			strings.TrimSpace(string(rule.Severity)),
			strings.TrimSpace(string(rule.Target)),
			strings.TrimSpace(rule.Pattern),
		}, "|"))
	}
	slices.Sort(canonical)
	hasher := sha256.New()
	for _, line := range canonical {
		_, _ = io.WriteString(hasher, line)
		_, _ = io.WriteString(hasher, "\n")
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

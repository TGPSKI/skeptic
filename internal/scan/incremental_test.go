package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

func TestIncrementalStateCacheRulesChangedAndShouldScan(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	filePath := filepath.Join(root, "a.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	loaded := ScanState{
		Version:     ScanStateVersion,
		RulesetHash: "oldhash",
		EntriesByAbs: map[string]ScanStateRecord{
			filepath.Clean(filePath): {Size: 5, ModUnixNano: 0, SHA256: ""},
		},
	}
	raw, _ := json.Marshal(loaded)
	if err := os.WriteFile(statePath, raw, 0o644); err != nil {
		t.Fatalf("write state file: %v", err)
	}

	cache, err := NewIncrementalStateCache(statePath, "newhash", true, nil)
	if err != nil {
		t.Fatalf("NewIncrementalStateCache failed: %v", err)
	}
	if !cache.RulesChanged() {
		t.Fatalf("expected rules-changed when hash differs")
	}

	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	shouldScan, err := cache.ShouldScan(filePath, info)
	if err != nil {
		t.Fatalf("ShouldScan failed: %v", err)
	}
	if !shouldScan {
		t.Fatalf("expected full rescan when rules changed")
	}
}

func TestIncrementalStateCacheRecordFinalizeSaveLoad(t *testing.T) {
	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	a := filepath.Join(root, "a.txt")
	b := filepath.Join(root, "b.txt")
	if err := os.WriteFile(a, []byte("alpha"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(b, []byte("beta"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}

	cache, err := NewIncrementalStateCache(statePath, "hash-1", true, nil)
	if err != nil {
		t.Fatalf("NewIncrementalStateCache failed: %v", err)
	}
	infoA, _ := os.Stat(a)
	infoB, _ := os.Stat(b)
	cache.Record(a, infoA, "")
	cache.Record(b, infoB, "")
	delete(cache.seen, filepath.Clean(b))
	cache.Finalize(true, "hash-1")
	if _, ok := cache.state.EntriesByAbs[filepath.Clean(b)]; ok {
		t.Fatalf("expected unseen entry to be pruned on finalize")
	}
	if err := cache.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	cache2, err := NewIncrementalStateCache(statePath, "hash-1", true, nil)
	if err != nil {
		t.Fatalf("reload cache failed: %v", err)
	}
	if !cache2.Enabled() {
		t.Fatalf("expected enabled cache")
	}
	if cache2.Path() == "" {
		t.Fatalf("expected cache path to be resolved")
	}
}

func TestIncrementalShouldScanSkipsUnchangedWithHashRefresh(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "x.txt")
	state := filepath.Join(root, "state.json")
	content := []byte("same-content")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cache, err := NewIncrementalStateCache(state, "hash-a", true, nil)
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	info, _ := os.Stat(path)
	hash, _ := security.SHA256FileHex(path)
	cache.Record(path, info, hash)
	if err := cache.Save(); err != nil {
		t.Fatalf("save cache: %v", err)
	}

	// Touch file mtime while keeping content/size unchanged.
	nextTime := info.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, nextTime, nextTime); err != nil {
		t.Fatalf("chtimes failed: %v", err)
	}
	cache2, err := NewIncrementalStateCache(state, "hash-a", true, nil)
	if err != nil {
		t.Fatalf("load cache2: %v", err)
	}
	info2, _ := os.Stat(path)
	shouldScan, err := cache2.ShouldScan(path, info2)
	if err != nil {
		t.Fatalf("ShouldScan failed: %v", err)
	}
	if shouldScan {
		t.Fatalf("expected unchanged content with hash match to be skipped")
	}
}

func TestComputeRulesetHashDeterministic(t *testing.T) {
	rulesA := []model.Rule{
		{ID: "B", Title: "b", Category: "x", Mitre: "T1059", Severity: model.SeverityHigh, Target: model.TargetContent, Pattern: "bbb"},
		{ID: "A", Title: "a", Category: "x", Mitre: "T1059", Severity: model.SeverityLow, Target: model.TargetPath, Pattern: "aaa"},
	}
	rulesB := []model.Rule{rulesA[1], rulesA[0]}
	if ComputeRulesetHash(rulesA) != ComputeRulesetHash(rulesB) {
		t.Fatalf("expected ruleset hash to be order-independent")
	}
}

func TestIncrementalSaveRequiresPath(t *testing.T) {
	cache := &IncrementalStateCache{enabled: true}
	if err := cache.Save(); err == nil {
		t.Fatalf("expected empty cache path to fail save")
	}
}

package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadProvenanceManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := ProvenanceManifest{"express": "abc123"}
	data, _ := json.Marshal(manifest)
	path := filepath.Join(dir, "provenance.json")
	os.WriteFile(path, data, 0o644)
	loaded, err := LoadProvenanceManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded["express"] != "abc123" {
		t.Fatalf("unexpected manifest content: %v", loaded)
	}
}

func TestExtractPackageHashesGosum(t *testing.T) {
	goSum := "github.com/pkg/errors v0.9.1 h1:YWJjMTIz\ngithub.com/pkg/errors v0.9.1/go.mod h1:ZGVmNDU2\n"
	hashes := ExtractPackageHashes("gosum", []byte(goSum))
	if len(hashes) != 2 {
		t.Fatalf("expected 2 go.sum entries, got %d", len(hashes))
	}
	if hashes["github.com/pkg/errors@v0.9.1"] != "h1:YWJjMTIz" {
		t.Fatalf("unexpected zip hash: %q", hashes["github.com/pkg/errors@v0.9.1"])
	}
	if hashes["github.com/pkg/errors@v0.9.1/go.mod"] != "h1:ZGVmNDU2" {
		t.Fatalf("unexpected go.mod hash: %q", hashes["github.com/pkg/errors@v0.9.1/go.mod"])
	}
}

func TestRunProvenanceChecksHappyPath(t *testing.T) {
	dir := t.TempDir()

	goSumContent := "github.com/pkg/errors v0.9.1 h1:YWJjMTIz\ngithub.com/pkg/errors v0.9.1/go.mod h1:ZGVmNDU2\n"
	goSumPath := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(goSumPath, []byte(goSumContent), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest := ProvenanceManifest{
		"github.com/pkg/errors@v0.9.1":        "h1:YWJjMTIz",
		"github.com/pkg/errors@v0.9.1/go.mod": "h1:ZGVmNDU2",
	}
	manifestData, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(dir, "provenance.json")
	if err := os.WriteFile(manifestPath, manifestData, 0o644); err != nil {
		t.Fatal(err)
	}

	findings := RunProvenanceChecks([]string{dir}, manifestPath, false, false, nil)
	for _, f := range findings {
		if f.RuleID == "PROV-001" {
			t.Errorf("unexpected hash mismatch finding: %v", f)
		}
	}
}

func TestRunProvenanceChecksHashMismatch(t *testing.T) {
	dir := t.TempDir()

	goSumContent := "github.com/pkg/errors v0.9.1 h1:YWJjMTIz\n"
	goSumPath := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(goSumPath, []byte(goSumContent), 0o644); err != nil {
		t.Fatal(err)
	}

	manifest := ProvenanceManifest{
		"github.com/pkg/errors@v0.9.1": "h1:DIFFERENT",
	}
	manifestData, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(dir, "provenance.json")
	if err := os.WriteFile(manifestPath, manifestData, 0o644); err != nil {
		t.Fatal(err)
	}

	findings := RunProvenanceChecks([]string{dir}, manifestPath, false, false, nil)
	found := false
	for _, f := range findings {
		if f.RuleID == "PROV-001" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PROV-001 hash mismatch finding")
	}
}

func TestExtractNpmLockHashes(t *testing.T) {
	lockJSON := `{
		"packages": {
			"node_modules/express": {
				"name": "express",
				"version": "4.18.2",
				"integrity": "sha512-abc123"
			}
		}
	}`
	hashes := ExtractNpmLockHashes([]byte(lockJSON))
	if len(hashes) != 1 {
		t.Fatalf("expected 1 npm hash entry, got %d", len(hashes))
	}
	if hashes["express@4.18.2"] != "sha512-abc123" {
		t.Fatalf("unexpected hash: %v", hashes)
	}
}

func TestNpmPackageNameFromLockPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"node_modules/express", "express"},
		{"node_modules/@scope/pkg", "@scope/pkg"},
		{"./node_modules/lodash", "lodash"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := NpmPackageNameFromLockPath(tt.path); got != tt.want {
			t.Errorf("NpmPackageNameFromLockPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestRunProvenanceChecksNoManifest(t *testing.T) {
	findings := RunProvenanceChecks([]string{t.TempDir()}, "", false, false, nil)
	if len(findings) != 0 {
		t.Fatal("expected no findings with empty manifest path")
	}
}

func TestRunProvenanceChecksMissingFile(t *testing.T) {
	findings := RunProvenanceChecks([]string{t.TempDir()}, "/nonexistent/manifest.json", false, false, nil)
	if len(findings) == 0 {
		t.Fatal("expected error finding for missing manifest")
	}
	if findings[0].RuleID != "PROV-ERR" {
		t.Fatalf("expected PROV-ERR, got %s", findings[0].RuleID)
	}
}

func TestExtractCargoLockHashes(t *testing.T) {
	data := `[[package]]
name = "serde"
version = "1.0.1"
checksum = "chk1"
[[package]]
name = "log"
version = "0.4"
`
	h := ExtractCargoLockHashes([]byte(data))
	if h["serde@1.0.1"] != "chk1" {
		t.Fatalf("got %v", h)
	}
	if _, ok := h["log@0.4"]; ok {
		t.Fatal("expected no checksum for second package")
	}
}

func TestExtractPnpmLockHashes(t *testing.T) {
	data := `
packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-abc}
`
	h := ExtractPnpmLockHashes([]byte(data))
	if h["lodash@4.17.21"] != "sha512-abc" {
		t.Fatalf("got %q", h["lodash@4.17.21"])
	}
}

func TestExtractYarnLockHashes(t *testing.T) {
	data := `
lodash@^4.17.21:
  version "4.17.21"
  integrity sha512-xyz
`
	h := ExtractYarnLockHashes([]byte(data))
	if h["lodash@4.17.21"] != "sha512-xyz" {
		t.Fatalf("got %v", h)
	}
}

func TestExtractPoetryLockHashes(t *testing.T) {
	data := `
[[package]]
name = "requests"
version = "2.31.0"

[metadata.files]
requests = [
    {file = "r.whl", hash = "sha256:deadbeef"},
]
`
	h := ExtractPoetryLockHashes([]byte(data))
	if h["requests@2.31.0"] != "sha256:deadbeef" {
		t.Fatalf("got %v", h)
	}
}

func TestLoadSignedProvenanceManifestEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkgs := ProvenanceManifest{"pkg@1": "h1:abc"}
	payload, err := json.Marshal(pkgs)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payload)
	dir := t.TempDir()
	path := filepath.Join(dir, "signed.json")
	wrapper := map[string]any{
		"packages":   pkgs,
		"signature":  hex.EncodeToString(sig),
		"public_key": hex.EncodeToString(pub),
	}
	raw, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, findings := LoadSignedProvenanceManifest(path, false)
	if loaded["pkg@1"] != "h1:abc" {
		t.Fatalf("manifest: %v", loaded)
	}
	for _, f := range findings {
		if f.RuleID == "PROV-004" {
			t.Fatalf("unexpected verify failure: %v", f)
		}
	}
}

func TestLoadSignedProvenanceManifestRequireSignedPlain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	if err := os.WriteFile(path, []byte(`{"a":"b"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings := LoadSignedProvenanceManifest(path, true)
	found := false
	for _, f := range findings {
		if f.RuleID == "PROV-003" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PROV-003")
	}
}

func TestRunProvenanceChecksStaleManifestEntry(t *testing.T) {
	dir := t.TempDir()
	goSum := "github.com/x/y v1.0.0 h1:YWJj\n"
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := ProvenanceManifest{
		"github.com/x/y@v1.0.0": "h1:YWJj",
		"orphan@1.0.0":          "sha512-zzz",
	}
	raw, _ := json.Marshal(manifest)
	path := filepath.Join(dir, "prov.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	findings := RunProvenanceChecks([]string{dir}, path, false, false, nil)
	found := false
	for _, f := range findings {
		if f.RuleID == "PROV-005" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PROV-005 for orphan manifest entry")
	}
}

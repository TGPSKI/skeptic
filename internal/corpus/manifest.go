package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Manifest is the top-level corpus.lock structure.
type Manifest struct {
	Version      int        `json:"version"`
	Created      string     `json:"created"`
	CorpusSHA256 string     `json:"corpus_sha256"`
	Artifacts    []Artifact `json:"artifacts"`
}

// Artifact is a single fetched and encrypted .md file in the corpus.
type Artifact struct {
	ID                   string   `json:"id"`
	OriginalName         string   `json:"original_name"`
	Source               string   `json:"source"`
	SourceType           string   `json:"source_type"`
	FetchTime            string   `json:"fetch_time"`
	PlaintextSHA256      string   `json:"plaintext_sha256"`
	EncryptedSHA256      string   `json:"encrypted_sha256"`
	SizeBytes            int64    `json:"size_bytes"`
	ExpectedRules        []string `json:"expected_rules,omitempty"`
	SanitizationsApplied []string `json:"sanitizations_applied,omitempty"`
	Metadata             []string `json:"metadata,omitempty"`
}

// NewManifest creates an empty manifest with version 1.
func NewManifest() Manifest {
	return Manifest{
		Version:   1,
		Created:   time.Now().UTC().Format(time.RFC3339),
		Artifacts: []Artifact{},
	}
}

// AddArtifact appends an artifact and recomputes the integrity hash.
func (m *Manifest) AddArtifact(a Artifact) {
	m.Artifacts = append(m.Artifacts, a)
}

// FindArtifact returns the artifact with the given ID, or nil.
func (m *Manifest) FindArtifact(id string) *Artifact {
	for i := range m.Artifacts {
		if m.Artifacts[i].ID == id {
			return &m.Artifacts[i]
		}
	}
	return nil
}

// TotalSizeBytes returns the sum of all artifact sizes.
func (m *Manifest) TotalSizeBytes() int64 {
	var total int64
	for _, a := range m.Artifacts {
		total += a.SizeBytes
	}
	return total
}

// WriteManifest serializes the manifest to the given path with integrity hash.
func WriteManifest(path string, m Manifest) error {
	m.CorpusSHA256 = ""
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("corpus: marshal manifest: %w", err)
	}
	h := sha256.Sum256(data)
	m.CorpusSHA256 = hex.EncodeToString(h[:])

	final, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("corpus: marshal manifest: %w", err)
	}
	final = append(final, '\n')
	if err := os.WriteFile(path, final, 0644); err != nil {
		return fmt.Errorf("corpus: write manifest: %w", err)
	}
	return nil
}

// ReadManifest reads and verifies the manifest from the given path.
func ReadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("corpus: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("corpus: parse manifest: %w", err)
	}
	if err := VerifyManifestIntegrity(data, m.CorpusSHA256); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// VerifyManifestIntegrity checks the SHA256 self-hash of the manifest.
func VerifyManifestIntegrity(rawData []byte, expectedHash string) error {
	if expectedHash == "" {
		return fmt.Errorf("corpus: manifest missing integrity hash")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rawData, &raw); err != nil {
		return fmt.Errorf("corpus: verify manifest: %w", err)
	}
	delete(raw, "corpus_sha256")

	var m Manifest
	if err := json.Unmarshal(rawData, &m); err != nil {
		return fmt.Errorf("corpus: verify manifest: %w", err)
	}
	m.CorpusSHA256 = ""
	canonical, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("corpus: verify manifest: %w", err)
	}
	h := sha256.Sum256(canonical)
	actual := hex.EncodeToString(h[:])
	if actual != expectedHash {
		return fmt.Errorf("corpus: manifest integrity check failed (expected %s, got %s)", expectedHash, actual)
	}
	return nil
}

// ArtifactFilter controls which artifacts are returned by FilterArtifacts.
// All non-empty fields are ANDed. String matches are case-insensitive substrings.
type ArtifactFilter struct {
	SourceType string
	Name       string
	Rule       string
	Source     string
}

// FilterArtifacts returns the subset of artifacts matching all non-empty filter fields.
func FilterArtifacts(artifacts []Artifact, f ArtifactFilter) []Artifact {
	if f.SourceType == "" && f.Name == "" && f.Rule == "" && f.Source == "" {
		return artifacts
	}
	var out []Artifact
	for _, a := range artifacts {
		if f.SourceType != "" && !strings.EqualFold(a.SourceType, f.SourceType) {
			continue
		}
		if f.Name != "" && !containsFold(a.OriginalName, f.Name) {
			continue
		}
		if f.Source != "" && !containsFold(a.Source, f.Source) {
			continue
		}
		if f.Rule != "" && !artifactHasRule(a, f.Rule) {
			continue
		}
		out = append(out, a)
	}
	return out
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func artifactHasRule(a Artifact, rule string) bool {
	rule = strings.ToLower(rule)
	for _, r := range a.ExpectedRules {
		if strings.Contains(strings.ToLower(r), rule) {
			return true
		}
	}
	return false
}

// SortArtifacts sorts artifacts in place. Valid keys: name, size, date, source-type.
// Prefix with "-" for descending (e.g. "-size").
func SortArtifacts(artifacts []Artifact, key string) {
	desc := strings.HasPrefix(key, "-")
	if desc {
		key = key[1:]
	}
	sort.SliceStable(artifacts, func(i, j int) bool {
		var less bool
		switch key {
		case "name":
			less = strings.ToLower(artifacts[i].OriginalName) < strings.ToLower(artifacts[j].OriginalName)
		case "size":
			less = artifacts[i].SizeBytes < artifacts[j].SizeBytes
		case "date":
			less = artifacts[i].FetchTime < artifacts[j].FetchTime
		case "source-type":
			less = strings.ToLower(artifacts[i].SourceType) < strings.ToLower(artifacts[j].SourceType)
		default:
			less = artifacts[i].FetchTime < artifacts[j].FetchTime
		}
		if desc {
			return !less
		}
		return less
	})
}

// Paginate returns a slice of artifacts for the given offset and limit.
// If limit <= 0, all artifacts from offset onward are returned.
func Paginate(artifacts []Artifact, offset, limit int) []Artifact {
	if offset >= len(artifacts) {
		return nil
	}
	if offset > 0 {
		artifacts = artifacts[offset:]
	}
	if limit > 0 && limit < len(artifacts) {
		artifacts = artifacts[:limit]
	}
	return artifacts
}

package corpus

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/security"
)

const defaultMaxCorpusBytes int64 = 50 * 1024 * 1024 // 50 MiB

// Corpus represents an initialized corpus directory.
type Corpus struct {
	Root     string
	Key      []byte
	Manifest Manifest
}

// Init creates a new corpus directory with encryption key, marker files, and empty manifest.
func Init(rawPath string, configValues map[string]string, scanTargets, mcpRoots []string) (string, error) {
	corpusPath, err := ResolveCorpusPath(rawPath, configValues)
	if err != nil {
		return "", err
	}
	resolved, err := ResolvePath(corpusPath)
	if err != nil {
		return "", err
	}
	if err := ValidateCorpusPath(resolved, scanTargets, mcpRoots); err != nil {
		return "", err
	}

	if _, err := os.Stat(filepath.Join(resolved, corpusMarkerFile)); err == nil {
		return "", fmt.Errorf("corpus: already initialized at %s", resolved)
	}

	if err := os.MkdirAll(resolved, 0700); err != nil {
		return "", fmt.Errorf("corpus: create directory: %w", err)
	}

	finalResolved, err := ResolvePath(resolved)
	if err != nil {
		return "", err
	}
	if finalResolved != resolved {
		if err := ValidateCorpusPath(finalResolved, scanTargets, mcpRoots); err != nil {
			os.Remove(resolved) //nolint:errcheck // best-effort cleanup
			return "", err
		}
		resolved = finalResolved
	}

	if err := os.MkdirAll(filepath.Join(resolved, artifactsDir), 0700); err != nil {
		return "", fmt.Errorf("corpus: create artifacts dir: %w", err)
	}

	key, err := GenerateKey()
	if err != nil {
		return "", err
	}
	if err := WriteKey(filepath.Join(resolved, corpusKeyFile), key); err != nil {
		return "", err
	}

	if err := WriteMarkerFiles(resolved); err != nil {
		return "", err
	}

	m := NewManifest()
	if err := WriteManifest(filepath.Join(resolved, corpusManifest), m); err != nil {
		return "", err
	}

	return resolved, nil
}

// Open loads an existing corpus from the given path.
func Open(rawPath string, configValues map[string]string) (*Corpus, error) {
	corpusPath, err := ResolveCorpusPath(rawPath, configValues)
	if err != nil {
		return nil, err
	}
	resolved, err := ResolvePath(corpusPath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(resolved, corpusMarkerFile)); err != nil {
		return nil, fmt.Errorf("corpus: not initialized at %s (missing %s)", resolved, corpusMarkerFile)
	}
	key, err := LoadKey(filepath.Join(resolved, corpusKeyFile))
	if err != nil {
		return nil, err
	}
	manifest, err := ReadManifest(filepath.Join(resolved, corpusManifest))
	if err != nil {
		return nil, err
	}
	return &Corpus{Root: resolved, Key: key, Manifest: manifest}, nil
}

// StoreArtifact encrypts and stores content as a corpus artifact.
func (c *Corpus) StoreArtifact(content []byte, originalName, source, sourceType string, expectedRules, sanitizations, metadata []string, maxCorpusBytes int64) error {
	if maxCorpusBytes <= 0 {
		maxCorpusBytes = defaultMaxCorpusBytes
	}
	if c.Manifest.TotalSizeBytes()+int64(len(content)) > maxCorpusBytes {
		return fmt.Errorf("corpus: would exceed max corpus size (%d bytes)", maxCorpusBytes)
	}

	plaintextHash := SHA256Hex(content)
	if c.Manifest.FindArtifact(plaintextHash) != nil {
		return fmt.Errorf("corpus: artifact already exists: %s", plaintextHash)
	}

	tagged := append([]byte(contentWarning), content...)
	ciphertext, err := Encrypt(c.Key, tagged)
	if err != nil {
		return err
	}

	encPath := filepath.Join(c.Root, artifactsDir, plaintextHash+".enc")
	tmpPath := encPath + ".tmp"
	if err := os.WriteFile(tmpPath, ciphertext, 0400); err != nil {
		return fmt.Errorf("corpus: write artifact: %w", err)
	}
	if err := os.Rename(tmpPath, encPath); err != nil {
		os.Remove(tmpPath) //nolint:errcheck // best-effort cleanup
		return fmt.Errorf("corpus: rename artifact: %w", err)
	}

	encHash, err := security.SHA256FileHex(encPath)
	if err != nil {
		return fmt.Errorf("corpus: hash encrypted artifact: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	stamped := make([]string, len(metadata))
	for i, m := range metadata {
		stamped[i] = now + " " + m
	}

	c.Manifest.AddArtifact(Artifact{
		ID:                   plaintextHash,
		OriginalName:         originalName,
		Source:               source,
		SourceType:           sourceType,
		FetchTime:            now,
		PlaintextSHA256:      plaintextHash,
		EncryptedSHA256:      encHash,
		SizeBytes:            int64(len(content)),
		ExpectedRules:        expectedRules,
		SanitizationsApplied: sanitizations,
		Metadata:             stamped,
	})

	return WriteManifest(filepath.Join(c.Root, corpusManifest), c.Manifest)
}

// DecryptArtifact decrypts an artifact and verifies its encrypted hash against the manifest.
func (c *Corpus) DecryptArtifact(a Artifact) ([]byte, error) {
	encPath := filepath.Join(c.Root, artifactsDir, a.ID+".enc")
	encHash, err := security.SHA256FileHex(encPath)
	if err != nil {
		return nil, fmt.Errorf("corpus: hash check: %w", err)
	}
	if encHash != a.EncryptedSHA256 {
		return nil, fmt.Errorf("corpus: artifact %s encrypted hash mismatch (expected %s, got %s)", a.ID, a.EncryptedSHA256, encHash)
	}

	ciphertext, err := os.ReadFile(encPath)
	if err != nil {
		return nil, fmt.Errorf("corpus: read artifact: %w", err)
	}
	plaintext, err := Decrypt(c.Key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("corpus: decrypt artifact %s: %w", a.ID, err)
	}

	if len(plaintext) > len(contentWarning) {
		prefix := string(plaintext[:len(contentWarning)])
		if prefix == contentWarning {
			plaintext = plaintext[len(contentWarning):]
		}
	}
	return plaintext, nil
}

// Info returns a human-readable summary of the corpus.
func (c *Corpus) Info() string {
	total := c.Manifest.TotalSizeBytes()
	return fmt.Sprintf("Corpus: %s\nArtifacts: %d\nTotal size: %d bytes\nCreated: %s\n",
		c.Root, len(c.Manifest.Artifacts), total, c.Manifest.Created)
}

// Purge removes the corpus directory after verifying the marker file.
func Purge(rawPath string, configValues map[string]string, confirm bool) error {
	corpusPath, err := ResolveCorpusPath(rawPath, configValues)
	if err != nil {
		return err
	}
	resolved, err := ResolvePath(corpusPath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(resolved, corpusMarkerFile)); err != nil {
		return fmt.Errorf("corpus: not a corpus directory (missing %s): %s", corpusMarkerFile, resolved)
	}
	if !confirm {
		return fmt.Errorf("corpus: would remove %s (%s). Pass --confirm to proceed", resolved, corpusMarkerFile)
	}
	return os.RemoveAll(resolved)
}

// Fetch acquires a .md file from a local path or URL, validates, sanitizes, encrypts, and stores it.
func (c *Corpus) Fetch(ctx context.Context, source string, opts FetchOptions) error {
	lockPath := filepath.Join(c.Root, corpusFetchLock)
	lock, err := AcquireFlock(lockPath)
	if err != nil {
		return err
	}
	defer ReleaseFlock(lock)

	var content []byte
	var originalName string
	var sanitizations []string
	var sourceType string

	if isURL(source) {
		content, originalName, sanitizations, err = FetchFromURL(ctx, source, opts)
		sourceType = "url"
	} else {
		content, originalName, sanitizations, err = FetchFromFile(source)
		sourceType = "file"
	}
	if err != nil {
		return err
	}

	return c.StoreArtifact(content, originalName, source, sourceType, opts.ExpectedRules, sanitizations, opts.Metadata, opts.MaxBytes)
}

// FindArtifactByPrefix returns the artifact whose ID starts with the given
// prefix. Returns nil if no match or if the prefix is ambiguous (multiple matches).
func (c *Corpus) FindArtifactByPrefix(prefix string) *Artifact {
	prefix = strings.ToLower(prefix)
	var match *Artifact
	for i := range c.Manifest.Artifacts {
		if strings.HasPrefix(strings.ToLower(c.Manifest.Artifacts[i].ID), prefix) {
			if match != nil {
				return nil
			}
			match = &c.Manifest.Artifacts[i]
		}
	}
	return match
}

// AppendMetadata adds an append-only timestamped metadata entry to the artifact
// identified by SHA prefix and rewrites the manifest.
func (c *Corpus) AppendMetadata(shaPrefix string, entry string) error {
	a := c.FindArtifactByPrefix(shaPrefix)
	if a == nil {
		return fmt.Errorf("corpus: no unique artifact matching prefix %q", shaPrefix)
	}
	stamped := time.Now().UTC().Format(time.RFC3339) + " " + entry
	a.Metadata = append(a.Metadata, stamped)
	return WriteManifest(filepath.Join(c.Root, corpusManifest), c.Manifest)
}

// SetExpectedRules replaces the expected_rules list for the artifact matching
// shaPrefix. Pass nil or empty to clear. The manifest is rewritten on success.
func (c *Corpus) SetExpectedRules(shaPrefix string, rules []string) error {
	a := c.FindArtifactByPrefix(shaPrefix)
	if a == nil {
		return fmt.Errorf("corpus: no unique artifact matching prefix %q", shaPrefix)
	}
	a.ExpectedRules = rules
	return WriteManifest(filepath.Join(c.Root, corpusManifest), c.Manifest)
}

func isURL(s string) bool {
	return len(s) > 8 && (s[:7] == "http://" || s[:8] == "https://")
}

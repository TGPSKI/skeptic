package report

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
)

// BundleOptions configures distribution bundle creation; Rules must be supplied by the caller (e.g. default rules from rules.DefaultRules()).
type BundleOptions struct {
	Platform    string
	OutPath     string
	SignBundle  bool
	PrivKeyPath string
	Rules       []model.Rule
	GoVersion   string
	Commit      string
}

// RunBundle creates a distribution bundle containing rules snapshot and manifest.
func RunBundle(stdout io.Writer, stderr io.Writer, opts BundleOptions) int {
	platform := strings.TrimSpace(opts.Platform)
	ruleSet := opts.Rules
	outPath := strings.TrimSpace(opts.OutPath)
	if outPath == "" {
		outPath = fmt.Sprintf("skeptic-bundle-%s-%s.tar.gz", strings.ReplaceAll(platform, "/", "-"), time.Now().UTC().Format("20060102"))
	}

	rulesJSON, err := json.MarshalIndent(ruleSet, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "failed marshaling rules snapshot: %v\n", err)
		return 1
	}
	rulesSnapSum := sha256.Sum256(rulesJSON)
	config := map[string]any{
		"preset":        "ci",
		"scan-style":    "hybrid",
		"policy-checks": true,
		"fail-on":       "high",
	}
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "failed marshaling config template: %v\n", err)
		return 1
	}
	manifest := map[string]any{
		"platform":              platform,
		"created_at":            time.Now().UTC().Format(time.RFC3339),
		"rule_count":            len(ruleSet),
		"go_version":            opts.GoVersion,
		"commit":                opts.Commit,
		"rules_snapshot_sha256": hex.EncodeToString(rulesSnapSum[:]),
	}

	file, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed creating bundle: %v\n", err)
		return 1
	}
	closeFile := true
	defer func() {
		if closeFile {
			if cerr := file.Close(); cerr != nil {
				fmt.Fprintf(stderr, "warning: close bundle file: %v\n", cerr)
			}
		}
	}()
	gw := gzip.NewWriter(file)
	tw := tar.NewWriter(gw)

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "failed marshaling manifest: %v\n", err)
		return 1
	}
	for name, data := range map[string][]byte{
		"manifest.json":        manifestJSON,
		"rules-snapshot.json":  rulesJSON,
		"config-template.json": configJSON,
	} {
		if err := AddTarEntry(tw, name, data); err != nil {
			fmt.Fprintf(stderr, "failed writing %s: %v\n", name, err)
			return 1
		}
	}

	if opts.SignBundle && strings.TrimSpace(opts.PrivKeyPath) != "" {
		allData := append(manifestJSON, rulesJSON...)
		hash := sha256.Sum256(allData)
		sig, signErr := SignWithEd25519(opts.PrivKeyPath, hash[:])
		if signErr != nil {
			fmt.Fprintf(stderr, "signing failed: %v\n", signErr)
			return 1
		}
		if err := AddTarEntry(tw, "signature.sig", sig); err != nil {
			fmt.Fprintf(stderr, "failed writing signature: %v\n", err)
			return 1
		}
		manifest["sha256"] = hex.EncodeToString(hash[:])
	}

	if err := tw.Close(); err != nil {
		fmt.Fprintf(stderr, "failed finalizing tar: %v\n", err)
		return 1
	}
	if err := gw.Close(); err != nil {
		fmt.Fprintf(stderr, "failed finalizing gzip: %v\n", err)
		return 1
	}
	closeFile = false
	if err := file.Close(); err != nil {
		fmt.Fprintf(stderr, "failed writing bundle file: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "bundle written: %s (%d rules)\n", outPath, len(ruleSet))
	return 0
}

// VerifyBundleOptions configures bundle signature verification.
type VerifyBundleOptions struct {
	BundlePath string
	PubKeyPath string
}

// RunVerifyBundle verifies a distribution bundle's signature and integrity.
func RunVerifyBundle(stdout io.Writer, stderr io.Writer, opts VerifyBundleOptions) int {
	bundlePath := strings.TrimSpace(opts.BundlePath)
	pubKeyPath := strings.TrimSpace(opts.PubKeyPath)
	if bundlePath == "" || pubKeyPath == "" {
		fmt.Fprintln(stderr, "--bundle and --pubkey are required")
		return 2
	}

	f, err := os.Open(bundlePath)
	if err != nil {
		fmt.Fprintf(stderr, "failed opening bundle: %v\n", err)
		return 1
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			fmt.Fprintf(stderr, "warning: close bundle file: %v\n", cerr)
		}
	}()
	gr, err := gzip.NewReader(f)
	if err != nil {
		fmt.Fprintf(stderr, "failed reading gzip: %v\n", err)
		return 1
	}
	defer func() {
		if cerr := gr.Close(); cerr != nil {
			fmt.Fprintf(stderr, "warning: gzip checksum validation failed: %v\n", cerr)
		}
	}()

	tr := tar.NewReader(gr)
	files := make(map[string][]byte)
	for {
		hdr, readErr := tr.Next()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			fmt.Fprintf(stderr, "tar read error: %v\n", readErr)
			return 1
		}
		data, readErr := io.ReadAll(io.LimitReader(tr, 10*1024*1024))
		if readErr != nil {
			fmt.Fprintf(stderr, "bundle read error for %s: %v\n", hdr.Name, readErr)
			return 1
		}
		files[hdr.Name] = data
	}

	manifestData, ok := files["manifest.json"]
	if !ok {
		fmt.Fprintln(stderr, "bundle missing manifest.json")
		return 1
	}
	rulesData := files["rules-snapshot.json"]
	if len(rulesData) == 0 {
		fmt.Fprintln(stderr, "bundle missing or empty rules-snapshot.json")
		return 1
	}
	sigData := files["signature.sig"]
	if len(sigData) == 0 {
		fmt.Fprintln(stderr, "bundle has no signature")
		return 1
	}

	var manifestObj map[string]any
	if err := json.Unmarshal(manifestData, &manifestObj); err != nil {
		fmt.Fprintf(stderr, "invalid manifest.json: %v\n", err)
		return 1
	}
	var rulesArr []json.RawMessage
	if err := json.Unmarshal(rulesData, &rulesArr); err != nil {
		fmt.Fprintf(stderr, "invalid rules-snapshot.json: %v\n", err)
		return 1
	}
	wantCount := -1
	switch v := manifestObj["rule_count"].(type) {
	case float64:
		wantCount = int(v)
	}
	if wantCount < 0 {
		fmt.Fprintln(stderr, "manifest missing or invalid rule_count")
		return 1
	}
	if wantCount != len(rulesArr) {
		fmt.Fprintf(stderr, "rule count mismatch: manifest rule_count=%d rules-snapshot has %d entries\n", wantCount, len(rulesArr))
		return 1
	}
	wantHex, ok := manifestObj["rules_snapshot_sha256"].(string)
	if !ok || strings.TrimSpace(wantHex) == "" {
		fmt.Fprintln(stderr, "manifest missing rules_snapshot_sha256")
		return 1
	}
	sumSnap := sha256.Sum256(rulesData)
	gotHex := hex.EncodeToString(sumSnap[:])
	if !strings.EqualFold(strings.TrimSpace(wantHex), gotHex) {
		fmt.Fprintf(stderr, "rules_snapshot_sha256 mismatch (manifest %q vs snapshot %q)\n", strings.TrimSpace(wantHex), gotHex)
		return 1
	}

	allData := append(manifestData, rulesData...)
	hash := sha256.Sum256(allData)

	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed reading public key: %v\n", err)
		return 1
	}
	pubKey, err := ParseEd25519PublicKeyPEM(pubKeyData)
	if err != nil {
		fmt.Fprintf(stderr, "invalid public key: %v\n", err)
		return 1
	}
	if !ed25519.Verify(pubKey, hash[:], sigData) {
		fmt.Fprintln(stderr, "signature verification FAILED")
		return 1
	}

	fmt.Fprintf(stdout, "bundle signature verified: %s\n", bundlePath)
	fmt.Fprintf(stdout, "sha256: %s\n", hex.EncodeToString(hash[:]))
	return 0
}

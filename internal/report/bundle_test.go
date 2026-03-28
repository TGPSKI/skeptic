package report

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/rules"
)

func TestRunBundleBasic(t *testing.T) {
	dir := t.TempDir()
	outPath := dir + "/test-bundle.tar.gz"
	var stdout, stderr strings.Builder
	code := RunBundle(&stdout, &stderr, BundleOptions{
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		OutPath:  outPath,
		Rules: []model.Rule{
			{ID: "TEST-001", Title: "Test", Severity: model.SeverityMedium, Pattern: "test"},
		},
	})
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bundle written") {
		t.Fatal("expected 'bundle written' in output")
	}
}

func TestRunVerifyBundleMissing(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunVerifyBundle(&stdout, &stderr, VerifyBundleOptions{})
	if code == 0 {
		t.Fatal("expected non-zero exit for missing args")
	}
}

func TestRunBundleIncludesAllRulesAndManifestRulesSHA256(t *testing.T) {
	dir := t.TempDir()
	outPath := dir + "/bundle.tar.gz"
	rules := make([]model.Rule, 12)
	for i := range rules {
		rules[i] = model.Rule{
			ID: fmt.Sprintf("ID-%02d", i), Title: "t", Severity: model.SeverityLow, Pattern: "p",
		}
	}
	var stdout, stderr strings.Builder
	if code := RunBundle(&stdout, &stderr, BundleOptions{
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
		OutPath:  outPath,
		Rules:    rules,
	}); code != 0 {
		t.Fatalf("RunBundle exit %d: %s", code, stderr.String())
	}
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var manifestData, rulesData []byte
	for {
		hdr, rErr := tr.Next()
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			t.Fatal(rErr)
		}
		data, rErr := io.ReadAll(io.LimitReader(tr, 20*1024*1024))
		if rErr != nil {
			t.Fatal(rErr)
		}
		switch hdr.Name {
		case "manifest.json":
			manifestData = data
		case "rules-snapshot.json":
			rulesData = data
		}
	}
	var snap []json.RawMessage
	if err := json.Unmarshal(rulesData, &snap); err != nil {
		t.Fatalf("rules snapshot: %v", err)
	}
	if len(snap) != len(rules) {
		t.Fatalf("rules in snapshot: got %d want %d", len(snap), len(rules))
	}
	sum := sha256.Sum256(rulesData)
	var manifest map[string]any
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	got, _ := manifest["rules_snapshot_sha256"].(string)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("rules_snapshot_sha256: got %q want %q", got, want)
	}
}

func TestRunVerifyBundleSignedManifestAndRuleCount(t *testing.T) {
	dir := t.TempDir()
	privDER, pubDER, err := rules.GenerateRulepackKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	if err := rules.WritePEMFile(privPath, "PRIVATE KEY", privDER, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rules.WritePEMFile(pubPath, "PUBLIC KEY", pubDER, 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "bundle.tar.gz")
	rulesIn := []model.Rule{
		{ID: "V-001", Title: "a", Severity: model.SeverityLow, Pattern: "x"},
		{ID: "V-002", Title: "b", Severity: model.SeverityLow, Pattern: "y"},
	}
	var stdout, stderr strings.Builder
	if code := RunBundle(&stdout, &stderr, BundleOptions{
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		OutPath:     outPath,
		SignBundle:  true,
		PrivKeyPath: privPath,
		Rules:       rulesIn,
	}); code != 0 {
		t.Fatalf("RunBundle exit %d: %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := RunVerifyBundle(&stdout, &stderr, VerifyBundleOptions{
		BundlePath: outPath,
		PubKeyPath: pubPath,
	}); code != 0 {
		t.Fatalf("RunVerifyBundle exit %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "bundle signature verified") {
		t.Fatalf("expected verify success in stdout: %q", stdout.String())
	}
}

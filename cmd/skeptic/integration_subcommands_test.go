//go:build integration

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

// readTarGzFiles extracts all regular file entries from a .tar.gz into name -> contents.
func readTarGzFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open bundle: %v", err)
	}
	defer func() { _ = f.Close() }()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()
	tr := tar.NewReader(gr)
	out := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != 0 {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, 50*1024*1024))
		if err != nil {
			t.Fatalf("read %s: %v", hdr.Name, err)
		}
		out[hdr.Name] = data
	}
	return out
}

func runSkepticExitCode(t *testing.T, binary string, wantCode int, args ...string) (stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cmd := exec.Command(binary, args...)
	cmd.Env = isolatedIntegrationEnv(t)
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("exec failed: %v\nargs=%v", err, args)
		}
	}
	if code != wantCode {
		t.Fatalf("exit code: got %d want %d\nargs=%v\nstdout:\n%s\nstderr:\n%s", code, wantCode, args, outBuf.String(), errBuf.String())
	}
	return outBuf.String(), errBuf.String()
}

func writeDeepModeFixture(t *testing.T, root string) {
	t.Helper()
	// Heuristic (non-wedge) finding: OBF-CMD-* — suppressed in developer mode unless critical.
	badJS := `// x
const _ = eval(atob('Zm9v'));
eval('a'+'b');
` + strings.Repeat("x", 180)
	if err := os.WriteFile(filepath.Join(root, "bad.js"), []byte(badJS), 0o644); err != nil {
		t.Fatalf("write bad.js: %v", err)
	}
	// Definitive SCM-* finding: appears in both developer and deep.
	pipe := "curl https://raw.githubusercontent.com/example/r/install.sh | bash\n"
	if err := os.WriteFile(filepath.Join(root, "remote_bootstrap.sh"), []byte(pipe), 0o644); err != nil {
		t.Fatalf("write remote_bootstrap.sh: %v", err)
	}
}

func TestIntegrationBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	binary := buildIntegrationBinary(t)
	outPath := filepath.Join(t.TempDir(), "bundle.tar.gz")
	stdout, _ := runSkepticExitCode(t, binary, 0, "bundle", "-o", outPath)
	if !strings.Contains(stdout, "bundle written") {
		t.Fatalf("expected stdout to mention bundle written, got: %q", stdout)
	}
	if st, err := os.Stat(outPath); err != nil || st.Size() == 0 {
		t.Fatalf("bundle file missing or empty: %v", err)
	}
	files := readTarGzFiles(t, outPath)
	for _, name := range []string{"manifest.json", "rules-snapshot.json", "config-template.json"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("bundle missing %s (have: %v)", name, tarMemberNames(files))
		}
	}
	var manifest map[string]any
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	rc, _ := manifest["rule_count"].(float64)
	if int(rc) <= 0 {
		t.Fatalf("expected rule_count > 0, got %v", manifest["rule_count"])
	}
	platform, _ := manifest["platform"].(string)
	if strings.TrimSpace(platform) == "" {
		t.Fatalf("expected platform set, got %q", platform)
	}
	if s, _ := manifest["rules_snapshot_sha256"].(string); strings.TrimSpace(s) == "" {
		t.Fatalf("expected rules_snapshot_sha256, got %v", manifest["rules_snapshot_sha256"])
	}
	var rulesArr []json.RawMessage
	if err := json.Unmarshal(files["rules-snapshot.json"], &rulesArr); err != nil {
		t.Fatalf("rules-snapshot.json: %v", err)
	}
	if len(rulesArr) != int(rc) {
		t.Fatalf("rules-snapshot length %d != manifest rule_count %d", len(rulesArr), int(rc))
	}
}

func TestIntegrationBundleSignVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	binary := buildIntegrationBinary(t)
	tmp := t.TempDir()
	priv1 := filepath.Join(tmp, "k1.pem")
	pub1 := filepath.Join(tmp, "k1.pub.pem")
	runSkepticExitCode(t, binary, 0, "gen-rule-keypair", "--private-out", priv1, "--public-out", pub1)

	signedPath := filepath.Join(tmp, "signed.tar.gz")
	stdout, _ := runSkepticExitCode(t, binary, 0, "bundle", "-o", signedPath, "--sign", "--private-key", priv1)
	if !strings.Contains(stdout, "bundle written") {
		t.Fatalf("expected bundle written in stdout: %q", stdout)
	}

	verifyOut, _ := runSkepticExitCode(t, binary, 0, "verify-bundle", "--bundle", signedPath, "--public-key", pub1)
	if !strings.Contains(strings.ToLower(verifyOut), "signature verified") {
		t.Fatalf("expected signature verified in stdout, got: %q", verifyOut)
	}

	t.Run("wrongPublicKey", func(t *testing.T) {
		priv2 := filepath.Join(tmp, "k2.pem")
		pub2 := filepath.Join(tmp, "k2.pub.pem")
		runSkepticExitCode(t, binary, 0, "gen-rule-keypair", "--private-out", priv2, "--public-out", pub2)
		_, verifyStderr := runSkepticExitCode(t, binary, 1, "verify-bundle", "--bundle", signedPath, "--public-key", pub2)
		low := strings.ToLower(verifyStderr)
		if !strings.Contains(low, "fail") && !strings.Contains(low, "invalid") {
			t.Fatalf("expected verification failure on stderr, got: %q", verifyStderr)
		}
	})
}

func TestIntegrationExportEvidence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	binary := buildIntegrationBinary(t)
	root := t.TempDir()
	writeDeepModeFixture(t, root)

	reportPath := filepath.Join(t.TempDir(), "scan-report.json")
	var repFile *os.File
	var err error
	if repFile, err = os.Create(reportPath); err != nil {
		t.Fatalf("create report file: %v", err)
	}
	scanCmd := exec.Command(binary, "scan", "--path", root, "--format", "json", "--fail-on", "none", "--policy-checks=false", "--quiet")
	scanCmd.Env = isolatedIntegrationEnv(t)
	scanCmd.Stdout = repFile
	var scanStderr bytes.Buffer
	scanCmd.Stderr = &scanStderr
	if err := scanCmd.Run(); err != nil {
		_ = repFile.Close()
		t.Fatalf("scan failed: %v stderr=%s", err, scanStderr.String())
	}
	if err := repFile.Close(); err != nil {
		t.Fatalf("close report: %v", err)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var preExport model.Report
	if err := json.Unmarshal(reportData, &preExport); err != nil {
		t.Fatalf("parse scan report: %v", err)
	}
	wantFindings := len(preExport.Findings)

	evidencePath := filepath.Join(t.TempDir(), "evidence.tar.gz")
	expOut, _ := runSkepticExitCode(t, binary, 0, "export-evidence", "--report", reportPath, "-o", evidencePath)
	if !strings.Contains(expOut, "evidence bundle written") {
		t.Fatalf("expected evidence bundle written, got: %q", expOut)
	}

	evFiles := readTarGzFiles(t, evidencePath)
	for _, name := range []string{"findings.json", "manifest.json", "snippets.json"} {
		if _, ok := evFiles[name]; !ok {
			t.Fatalf("evidence missing %s (have %v)", name, tarMemberNames(evFiles))
		}
	}
	var man map[string]any
	if err := json.Unmarshal(evFiles["manifest.json"], &man); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	tf, _ := man["total_findings"].(float64)
	if int(tf) != wantFindings {
		t.Fatalf("manifest total_findings=%v want %d", man["total_findings"], wantFindings)
	}
	var exported model.Report
	if err := json.Unmarshal(evFiles["findings.json"], &exported); err != nil {
		t.Fatalf("findings.json: %v", err)
	}
	if len(exported.Findings) != wantFindings {
		t.Fatalf("exported findings count %d vs scan %d", len(exported.Findings), wantFindings)
	}
}

func TestIntegrationIngest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	binary := buildIntegrationBinary(t)
	tmp := t.TempDir()
	stixPath := filepath.Join(tmp, "intel-stix.json")
	stix := map[string]any{
		"type": "bundle",
		"id":   "bundle--integration-test",
		"objects": []map[string]any{
			{
				"type":    "indicator",
				"name":    "Integration STIX IOC",
				"pattern": "[domain-name:value = 'evil.integration.test']",
			},
		},
	}
	raw, err := json.Marshal(stix)
	if err != nil {
		t.Fatalf("marshal stix: %v", err)
	}
	if err := os.WriteFile(stixPath, raw, 0o644); err != nil {
		t.Fatalf("write stix: %v", err)
	}
	outPack := filepath.Join(tmp, "ingested-rules.json")
	runSkepticExitCode(t, binary, 0,
		"ingest",
		"--source", stixPath,
		"--input-format", "stix",
		"--out", outPack,
		"--name", "test-ingest",
		"--max-rules", "500",
	)
	packData, err := os.ReadFile(outPack)
	if err != nil {
		t.Fatalf("read rulepack: %v", err)
	}
	var pack model.RulePack
	if err := json.Unmarshal(packData, &pack); err != nil {
		t.Fatalf("parse rulepack: %v", err)
	}
	found := false
	for _, spec := range pack.Rules {
		if strings.TrimSpace(spec.Pattern) != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected at least one rule spec with non-empty pattern, got %d rules", len(pack.Rules))
	}
}

func TestIntegrationDeepMode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	binary := buildIntegrationBinary(t)
	root := t.TempDir()
	writeDeepModeFixture(t, root)

	common := []string{
		"scan", "--path", root, "--format", "json", "--fail-on", "none", "--policy-checks=false", "--quiet", "--profile", "repo",
	}

	t.Run("deepReportModeAndFindings", func(t *testing.T) {
		deep, _ := runSkepticJSONReport(t, binary, append(common, "--mode", "deep")...)
		if deep.Mode != model.ScanModeDeep {
			t.Fatalf("report.Mode=%q want deep", deep.Mode)
		}
		if len(deep.Findings) == 0 {
			t.Fatal("expected at least one finding in deep mode")
		}
	})

	t.Run("developerVsDeepFiltering", func(t *testing.T) {
		deep, _ := runSkepticJSONReport(t, binary, append(common, "--mode", "deep")...)
		dev, _ := runSkepticJSONReport(t, binary, append(common, "--mode", "developer")...)
		if dev.Mode != model.ScanModeDeveloper {
			t.Fatalf("report.Mode=%q want developer", dev.Mode)
		}
		if len(deep.Findings) < len(dev.Findings) {
			t.Fatalf("deep should not have fewer findings than developer: deep=%d dev=%d", len(deep.Findings), len(dev.Findings))
		}
		deepIDs := findingRuleIDSet(t, deep)
		devIDs := findingRuleIDSet(t, dev)
		for id := range devIDs {
			if _, ok := deepIDs[id]; !ok {
				t.Fatalf("developer finding rule_id %q missing from deep report", id)
			}
		}
		extra := 0
		for id := range deepIDs {
			if _, ok := devIDs[id]; !ok {
				extra++
			}
		}
		if extra == 0 && len(deep.Findings) == len(dev.Findings) {
			t.Fatal("expected deep mode to surface findings dropped in developer mode (heuristic non-critical); check fixture")
		}
	})
}

func tarMemberNames(m map[string][]byte) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

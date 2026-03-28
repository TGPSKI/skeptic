package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/rules"
)

func TestRunValidationErrors(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var out, errBuf bytes.Buffer
	if code := run([]string{"--diff-only"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected diff-only validation exit code 2, got %d", code)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"--format", "wat"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected format validation exit code 2, got %d", code)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"--scan-style", "wat"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected scan-style validation exit code 2, got %d", code)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"--threat-mode", "wat"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected threat-mode validation exit code 2, got %d", code)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"--preset", "wat"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected preset validation exit code 2, got %d", code)
	}
}

func TestRunJSONAndSARIFOutputs(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	root := t.TempDir()
	writeFixture(t, root, "note.txt", "safe content")

	var out, errBuf bytes.Buffer
	code := run([]string{
		"--path", root,
		"--format", "json",
		"--fail-on", "none",
		"--max-files", "100",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("json run exit=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"findings"`) {
		t.Fatalf("expected JSON report output, got %q", out.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"--path", root,
		"--format", "sarif",
		"--fail-on", "none",
		"--max-files", "100",
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("sarif run exit=%d stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) {
		t.Fatalf("expected SARIF output, got %q", out.String())
	}
}

func TestUnknownSubcommandReturnsError(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var out, errBuf bytes.Buffer
	code := run([]string{"info"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected unknown subcommand exit code 2, got %d", code)
	}
	if !strings.Contains(errBuf.String(), `unknown command "info"`) {
		t.Fatalf("expected 'unknown command' in stderr, got %q", errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{"bogus-cmd"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected unknown subcommand exit code 2, got %d", code)
	}
	if !strings.Contains(errBuf.String(), `unknown command "bogus-cmd"`) {
		t.Fatalf("expected 'unknown command' in stderr, got %q", errBuf.String())
	}
}

func TestCorpusScanFormatValidation(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var out, errBuf bytes.Buffer
	code := run([]string{"corpus", "scan", "--format", "yaml"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected corpus scan --format yaml to exit 2, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "invalid --format") {
		t.Fatalf("expected format validation error, got %q", errBuf.String())
	}
}

func TestCorpusScanFailOnValidation(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	var out, errBuf bytes.Buffer
	code := run([]string{"corpus", "scan", "--fail-on", "bogus"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("expected corpus scan --fail-on bogus to exit 2, got %d", code)
	}
	if !strings.Contains(errBuf.String(), "invalid --fail-on") {
		t.Fatalf("expected fail-on validation error, got %q", errBuf.String())
	}
}

func TestRunSubcommandDispatch(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	var out, errBuf bytes.Buffer
	if code := run([]string{"ingest"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected ingest missing-source to return 2, got %d", code)
	}

	root := t.TempDir()
	priv := filepath.Join(root, "signing.key.pem")
	pub := filepath.Join(root, "signing.pub.pem")
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"gen-rule-keypair", "--private-out", priv, "--public-out", pub}, &out, &errBuf); code != 0 {
		t.Fatalf("gen-rule-keypair dispatch exit=%d stderr=%s", code, errBuf.String())
	}
	if _, err := os.Stat(priv); err != nil {
		t.Fatalf("expected generated private key: %v", err)
	}
	if _, err := os.Stat(pub); err != nil {
		t.Fatalf("expected generated public key: %v", err)
	}

	rulesFile := filepath.Join(root, "rules.json")
	if err := os.WriteFile(rulesFile, []byte(`[]`), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"sign-rulepack", "--rules-file", rulesFile, "--private-key", priv}, &out, &errBuf); code != 0 {
		t.Fatalf("sign-rulepack dispatch exit=%d stderr=%s", code, errBuf.String())
	}
	if _, err := os.Stat(rules.DefaultRulepackSignaturePath(rulesFile)); err != nil {
		t.Fatalf("expected signature output file: %v", err)
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"serve", "--scan-interval", "wat"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected serve validation to return 2, got %d", code)
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"mcp", "--daemon-url", "http://example.com:7788"}, &out, &errBuf); code != 2 {
		t.Fatalf("expected mcp loopback validation to return 2, got %d", code)
	}

	out.Reset()
	errBuf.Reset()
	initPath := filepath.Join(root, ".skeptic.test.json")
	if code := run([]string{"init-config", "--out", initPath, "--format", "json"}, &out, &errBuf); code != 0 {
		t.Fatalf("init-config dispatch exit=%d stderr=%s", code, errBuf.String())
	}
	if _, err := os.Stat(initPath); err != nil {
		t.Fatalf("expected init-config output file: %v", err)
	}

	out.Reset()
	errBuf.Reset()
	initPath2 := filepath.Join(root, ".skeptic.test2.json")
	if code := run([]string{"init", "--out", initPath2, "--format", "json"}, &out, &errBuf); code != 0 {
		t.Fatalf("init dispatch exit=%d stderr=%s", code, errBuf.String())
	}
	if _, err := os.Stat(initPath2); err != nil {
		t.Fatalf("expected init output file: %v", err)
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"config", "show"}, &out, &errBuf); code != 0 {
		t.Fatalf("config show dispatch exit=%d stderr=%s", code, errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"config", "use", "nonexistent"}, &out, &errBuf); code != 2 {
		t.Fatalf("config use missing profile should exit 2, got %d", code)
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"config"}, &out, &errBuf); code != 0 {
		t.Fatalf("bare config should exit 0, got %d stderr=%s", code, errBuf.String())
	}
}

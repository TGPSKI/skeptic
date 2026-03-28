package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/checks"
	"github.com/TGPSKI/skeptic/internal/correlation"
	"github.com/TGPSKI/skeptic/internal/ingest"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/rules"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
)

func BenchmarkDefaultRulesCompile(b *testing.B) {
	r := rules.DefaultRules()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, rule := range r {
			regexp.Compile(rule.Pattern)
		}
	}
}

func BenchmarkSplitRulesByTarget(b *testing.B) {
	r := rules.DefaultRules()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanpkg.SplitRulesByTarget(r)
	}
}

func benchCorpus(b *testing.B, fileCount, linesPerFile int) string {
	b.Helper()
	root := b.TempDir()
	for i := 0; i < fileCount; i++ {
		var sb strings.Builder
		for j := 0; j < linesPerFile; j++ {
			fmt.Fprintf(&sb, "line %d: normal code content var_%d = value_%d\n", j, j, j)
		}
		sb.WriteString("eval(Buffer.from('dGVzdA==','base64').toString())\n")
		path := filepath.Join(root, fmt.Sprintf("file_%04d.js", i))
		os.WriteFile(path, []byte(sb.String()), 0o644)
	}
	return root
}

func BenchmarkScanFile_SmallFile(b *testing.B) {
	root := benchCorpus(b, 1, 50)
	r := rules.DefaultRules()
	pathRules, contentRules := scanpkg.SplitRulesByTarget(r)
	path := filepath.Join(root, "file_0000.js")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanpkg.ScanSingleFile(path, root, pathRules, contentRules, scanpkg.ScanFileOptions{
			MaxBytes: 2 * 1024 * 1024, IgnorePermissionErrors: true,
			MaxFindingsPerFile: 100, ScanStyle: model.ScanStyleHybrid,
			ThreatMode: model.ThreatModeAll, PolicyChecks: true,
		})
	}
}

func BenchmarkScanFile_MediumFile(b *testing.B) {
	root := benchCorpus(b, 1, 500)
	r := rules.DefaultRules()
	pathRules, contentRules := scanpkg.SplitRulesByTarget(r)
	path := filepath.Join(root, "file_0000.js")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanpkg.ScanSingleFile(path, root, pathRules, contentRules, scanpkg.ScanFileOptions{
			MaxBytes: 2 * 1024 * 1024, IgnorePermissionErrors: true,
			MaxFindingsPerFile: 100, ScanStyle: model.ScanStyleHybrid,
			ThreatMode: model.ThreatModeAll, PolicyChecks: true,
		})
	}
}

func BenchmarkScanFile_LargeFile(b *testing.B) {
	root := benchCorpus(b, 1, 5000)
	r := rules.DefaultRules()
	pathRules, contentRules := scanpkg.SplitRulesByTarget(r)
	path := filepath.Join(root, "file_0000.js")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanpkg.ScanSingleFile(path, root, pathRules, contentRules, scanpkg.ScanFileOptions{
			MaxBytes: 2 * 1024 * 1024, IgnorePermissionErrors: true,
			MaxFindingsPerFile: 100, ScanStyle: model.ScanStyleHybrid,
			ThreatMode: model.ThreatModeAll, PolicyChecks: true,
		})
	}
}

func BenchmarkDecodePayloadLayers_Base64(b *testing.B) {
	raw := []byte("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgLXMgaHR0cDovL2V2aWwuY29tL3NoZWxsLnNoIHwgYmFzaCIp")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanpkg.DecodePayloadLayers(raw)
	}
}

func BenchmarkDecodePayloadLayers_Hex(b *testing.B) {
	raw := []byte("6375726c202d73206874747073")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanpkg.DecodePayloadLayers(raw)
	}
}

func BenchmarkDecodePayloadLayers_Nested(b *testing.B) {
	raw := []byte("WTNWeWJDQXRjeUJvZEhSd2N6b3ZMMlYyYVd3dVkyOXQ=")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanpkg.DecodePayloadLayers(raw)
	}
}

func BenchmarkParseSTIXBundle(b *testing.B) {
	bundle := buildSTIXBundleJSON(50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ingest.ParseSTIXBundle(bundle) //nolint:errcheck
	}
}

func BenchmarkParseSigmaRule(b *testing.B) {
	sigma := buildSigmaRuleYAML(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ingest.ParseSigmaRule(sigma)
	}
}

func BenchmarkParseYARAStrings(b *testing.B) {
	yara := buildYARARule(30)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ingest.ParseYARAStrings(yara)
	}
}

func BenchmarkCorrelation_SmallCorpus(b *testing.B) {
	findings := generateSyntheticFindings(10, 3)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		correlation.RunCorrelation(findings)
	}
}

func BenchmarkCorrelation_LargeCorpus(b *testing.B) {
	findings := generateSyntheticFindings(100, 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		correlation.RunCorrelation(findings)
	}
}

func BenchmarkEditDistance(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checks.EditDistance("express", "expreess")
		checks.EditDistance("lodash", "l0dash")
		checks.EditDistance("react", "raect")
	}
}

func BenchmarkDetectFeedFormat(b *testing.B) {
	stix := `{"type":"bundle","id":"bundle--1","objects":[{"type":"indicator"}]}`
	sigma := "title: Test\nlogsource:\n  product: linux\ndetection:\n  sel:\n    cmd: 'test'\n"
	yara := "rule foo {\n    strings:\n        $a = \"test\"\n    condition:\n        $a\n}\n"
	plain := "just some text with no structured format"
	b.Run("STIX", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ingest.DetectFeedFormat("auto", stix)
		}
	})
	b.Run("Sigma", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ingest.DetectFeedFormat("auto", sigma)
		}
	})
	b.Run("YARA", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ingest.DetectFeedFormat("auto", yara)
		}
	})
	b.Run("Plain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ingest.DetectFeedFormat("auto", plain)
		}
	})
}

// --- Helpers ---

func buildSTIXBundleJSON(indicators int) []byte {
	var sb strings.Builder
	sb.WriteString(`{"type":"bundle","id":"bundle--bench","objects":[`)
	for i := 0; i < indicators; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `{"type":"indicator","name":"ind-%d","pattern":"[domain-name:value = 'evil%d.example.com']"}`, i, i)
	}
	sb.WriteString(`]}`)
	return []byte(sb.String())
}

func buildSigmaRuleYAML(detections int) []byte {
	var sb strings.Builder
	sb.WriteString("title: Bench Sigma Rule\n")
	sb.WriteString("id: bench-sigma\n")
	sb.WriteString("logsource:\n  product: windows\ndetection:\n")
	for i := 0; i < detections; i++ {
		fmt.Fprintf(&sb, "  field_%d: 'suspicious_value_%d'\n", i, i)
	}
	sb.WriteString("level: high\n")
	return []byte(sb.String())
}

func buildYARARule(strings_ int) []byte {
	var sb strings.Builder
	sb.WriteString("rule bench_rule {\n    strings:\n")
	for i := 0; i < strings_; i++ {
		fmt.Fprintf(&sb, "        $s%d = \"malicious_payload_%04d\"\n", i, i)
	}
	sb.WriteString("    condition:\n        any of them\n}\n")
	return []byte(sb.String())
}

func generateSyntheticFindings(fileCount, findingsPerFile int) []model.Finding {
	var findings []model.Finding
	ruleIDs := []string{"SCM-TRUST-001", "CI-SECRET-001", "AGT-MCP-001", "AGT-SKL-001", "ENC-EXFIL-001"}
	for f := 0; f < fileCount; f++ {
		dir := fmt.Sprintf("/repo/dir_%02d", f%5)
		for i := 0; i < findingsPerFile; i++ {
			findings = append(findings, model.Finding{
				File:     fmt.Sprintf("%s/file_%03d.js", dir, f),
				Line:     i + 1,
				RuleID:   ruleIDs[i%len(ruleIDs)],
				Severity: model.SeverityHigh,
			})
		}
	}
	return findings
}

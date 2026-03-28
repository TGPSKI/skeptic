package ingest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDetectFeedFormat_Explicit(t *testing.T) {
	tests := []struct {
		explicit string
		want     string
	}{
		{"stix", "stix"},
		{"SIGMA", "sigma"},
		{"yara", "yara"},
		{"YARA", "yara"},
	}
	for _, tc := range tests {
		got := DetectFeedFormat(tc.explicit, "anything")
		if got != tc.want {
			t.Errorf("DetectFeedFormat(%q, ...) = %q, want %q", tc.explicit, got, tc.want)
		}
	}
}

func TestDetectFeedFormat_Auto_STIX(t *testing.T) {
	stix := `{"type":"bundle","id":"bundle--1","objects":[{"type":"indicator","name":"test","pattern":"[file:name = 'evil.exe']"}]}`
	got := DetectFeedFormat("auto", stix)
	if got != "stix" {
		t.Errorf("expected stix, got %q", got)
	}
}

func TestDetectFeedFormat_Auto_Sigma(t *testing.T) {
	sigma := "title: Test Rule\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine: 'mimikatz'\nlevel: high\n"
	got := DetectFeedFormat("auto", sigma)
	if got != "sigma" {
		t.Errorf("expected sigma, got %q", got)
	}
}

func TestDetectFeedFormat_Auto_YARA(t *testing.T) {
	yara := `rule test_rule {
    strings:
        $a = "malicious_payload"
    condition:
        $a
}`
	got := DetectFeedFormat("auto", yara)
	if got != "yara" {
		t.Errorf("expected yara, got %q", got)
	}
}

func TestDetectFeedFormat_Auto_Unknown(t *testing.T) {
	got := DetectFeedFormat("auto", "just some random text content here")
	if got != "" {
		t.Errorf("expected empty string for unknown format, got %q", got)
	}
}

func TestParseSTIXBundle(t *testing.T) {
	bundle := map[string]interface{}{
		"type": "bundle",
		"id":   "bundle--abc",
		"objects": []map[string]interface{}{
			{
				"type":    "indicator",
				"name":    "Evil Domain",
				"pattern": "[domain-name:value = 'evil.example.com']",
			},
			{
				"type":    "indicator",
				"name":    "Malware Hash",
				"pattern": "[file:hashes.'SHA-256' = 'deadbeef1234']",
			},
			{
				"type": "malware",
				"name": "Not an indicator",
			},
		},
	}
	data, _ := json.Marshal(bundle)
	rules, err := ParseSTIXBundle(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].ID != "STIX-0001" {
		t.Errorf("first rule ID = %q, want STIX-0001", rules[0].ID)
	}
	if rules[0].Category != "threat-intel-stix" {
		t.Errorf("category = %q, want threat-intel-stix", rules[0].Category)
	}
	if !strings.Contains(rules[0].Pattern, "evil\\.example\\.com") {
		t.Errorf("pattern should contain escaped domain, got %q", rules[0].Pattern)
	}
}

func TestParseSTIXBundle_Empty(t *testing.T) {
	rules, err := ParseSTIXBundle([]byte(`{"type":"bundle","objects":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from empty bundle, got %d", len(rules))
	}
}

func TestParseSTIXBundle_InvalidJSON(t *testing.T) {
	rules, err := ParseSTIXBundle([]byte(`not json`))
	if err == nil {
		t.Error("expected error from invalid JSON")
	}
	if rules != nil {
		t.Errorf("expected nil from invalid JSON, got %v", rules)
	}
}

func TestExtractSTIXPatternValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"[domain-name:value = 'evil.com']", "evil.com"},
		{"[file:hashes.'SHA-256' = 'abc123']", "abc123"},
		{"[file:name ='test.exe']", "test.exe"},
		{"no pattern here", ""},
	}
	for _, tc := range tests {
		got := ExtractSTIXPatternValue(tc.input)
		if got != tc.want {
			t.Errorf("ExtractSTIXPatternValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestParseSigmaRule(t *testing.T) {
	sigma := `title: Mimikatz Usage
id: abc12345-6789
logsource:
  product: windows
  service: security
detection:
  selection:
    CommandLine: 'mimikatz.exe'
    ParentImage: 'cmd.exe'
  condition: selection
level: high
`
	rules := ParseSigmaRule([]byte(sigma))
	if len(rules) < 2 {
		t.Fatalf("expected at least 2 rules from sigma, got %d", len(rules))
	}
	if rules[0].Category != "threat-intel-sigma" {
		t.Errorf("category = %q, want threat-intel-sigma", rules[0].Category)
	}
	foundMimikatz := false
	for _, r := range rules {
		if strings.Contains(r.Pattern, "mimikatz") {
			foundMimikatz = true
		}
	}
	if !foundMimikatz {
		t.Error("expected a rule with mimikatz pattern")
	}
}

func TestParseSigmaRule_NoDetection(t *testing.T) {
	sigma := `title: Empty Rule
id: empty
logsource:
  product: linux
level: low
`
	rules := ParseSigmaRule([]byte(sigma))
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from sigma with no detection, got %d", len(rules))
	}
}

func TestParseYARAStrings(t *testing.T) {
	yara := `rule trojan_beacon {
    strings:
        $s1 = "beacon_payload_start"
        $s2 = "c2_callback_url"
        $short = "ab"
    condition:
        any of them
}
`
	rules := ParseYARAStrings([]byte(yara))
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (short string skipped), got %d", len(rules))
	}
	if !strings.Contains(rules[0].ID, "YARA-trojan_beacon") {
		t.Errorf("rule ID should contain YARA-trojan_beacon, got %q", rules[0].ID)
	}
	if rules[0].Category != "threat-intel-yara" {
		t.Errorf("category = %q, want threat-intel-yara", rules[0].Category)
	}
}

func TestParseYARAStrings_MultipleRules(t *testing.T) {
	yara := `rule rule_a {
    strings:
        $a = "payload_alpha"
    condition:
        $a
}

rule rule_b {
    strings:
        $b = "payload_beta"
    condition:
        $b
}
`
	rules := ParseYARAStrings([]byte(yara))
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules from two YARA rules, got %d", len(rules))
	}
}

func TestParseYARAStrings_NoStrings(t *testing.T) {
	yara := `rule no_strings {
    condition:
        true
}
`
	rules := ParseYARAStrings([]byte(yara))
	if len(rules) != 0 {
		t.Errorf("expected 0 rules from YARA with no strings, got %d", len(rules))
	}
}

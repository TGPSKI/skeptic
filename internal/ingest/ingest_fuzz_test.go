package ingest

import "testing"

func FuzzParseSTIXBundle(f *testing.F) {
	f.Add([]byte(`{"objects":[{"type":"indicator","name":"test","pattern":"[ipv4-addr:value = '1.2.3.4']"}]}`))
	f.Add([]byte(`{"objects":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		rules, _ := ParseSTIXBundle(data)
		for _, r := range rules {
			if r.ID == "" {
				t.Error("STIX rule with empty ID")
			}
			if r.Pattern == "" {
				t.Error("STIX rule with empty pattern")
			}
		}
	})
}

func FuzzParseSigmaRule(f *testing.F) {
	f.Add([]byte("title: Test\nid: abc123\ndetection:\n  selection:\n    field: value\nlogsource:\n  product: windows\nlevel: high\n"))
	f.Add([]byte("title: Empty\n"))
	f.Add([]byte("not yaml"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		rules := ParseSigmaRule(data)
		for _, r := range rules {
			if r.ID == "" {
				t.Error("Sigma rule with empty ID")
			}
		}
	})
}

func FuzzDetectFeedFormat(f *testing.F) {
	f.Add("auto", `{"type": "bundle", "objects": []}`)
	f.Add("auto", "title: Test\ndetection:\n  sel: val\nlogsource:\n  product: win\n")
	f.Add("auto", "rule test_rule { strings: $a = \"hello\" condition: $a }")
	f.Add("stix", "anything")
	f.Add("auto", "")
	f.Add("auto", "random text content")

	f.Fuzz(func(t *testing.T, explicit string, content string) {
		result := DetectFeedFormat(explicit, content)
		valid := map[string]bool{"": true, "stix": true, "sigma": true, "yara": true}
		if !valid[result] {
			t.Errorf("unexpected format result: %q", result)
		}
	})
}

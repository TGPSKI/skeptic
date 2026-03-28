package provenance

import (
	"strings"
	"testing"
)

func TestParseCycloneDXBOM(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"components": [
			{
				"name": "acme-lib",
				"version": "1.0.0",
				"hashes": [
					{"alg": "SHA-512", "content": "abcdef"}
				]
			}
		]
	}`)
	comps, err := ParseCycloneDXBOM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d components", len(comps))
	}
	if comps[0].Name != "acme-lib" || comps[0].Version != "1.0.0" {
		t.Fatalf("unexpected: %+v", comps[0])
	}
	if comps[0].Hashes["SHA-512"] != "abcdef" {
		t.Fatalf("hashes: %v", comps[0].Hashes)
	}
}

func TestParseSPDXBOM(t *testing.T) {
	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"name": "pkg-one",
				"versionInfo": "2.0.0",
				"checksums": [
					{"algorithm": "SHA256", "checksumValue": "001122"}
				]
			}
		]
	}`)
	comps, err := ParseSPDXBOM(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 1 {
		t.Fatalf("got %d packages", len(comps))
	}
	if comps[0].Name != "pkg-one" || comps[0].Version != "2.0.0" {
		t.Fatalf("unexpected: %+v", comps[0])
	}
	if comps[0].Hashes["SHA256"] != "001122" {
		t.Fatalf("hashes: %v", comps[0].Hashes)
	}
}

func TestCrossReferenceSBOM(t *testing.T) {
	sbom := []SBOMComponent{
		{Name: "only-sbom", Version: "1.0.0", Hashes: map[string]string{"SHA-512": "aa"}},
		{Name: "both", Version: "1.0.0", Hashes: map[string]string{"SHA-512": "match"}},
	}
	lock := map[string]string{
		"both@1.0.0":      "match",
		"only-lock@2.0.0": "x",
	}
	findings := CrossReferenceSBOM(sbom, lock, "/sbom.json", false)
	var has001, has002, has003 bool
	for _, f := range findings {
		switch f.RuleID {
		case "PROV-SBOM-001":
			has001 = true
			if !strings.Contains(f.Description, "only-sbom@1.0.0") {
				t.Errorf("001: %s", f.Description)
			}
		case "PROV-SBOM-002":
			has002 = true
			if !strings.Contains(f.Description, "only-lock@2.0.0") {
				t.Errorf("002: %s", f.Description)
			}
		case "PROV-SBOM-003":
			has003 = true
		}
	}
	if !has001 || !has002 {
		t.Fatalf("expected 001 and 002, got 001=%v 002=%v findings=%d", has001, has002, len(findings))
	}
	if has003 {
		t.Fatal("unexpected 003")
	}
}

func TestCrossReferenceSBOMHashMismatch(t *testing.T) {
	sbom := []SBOMComponent{
		{Name: "x", Version: "1.0.0", Hashes: map[string]string{"SHA-512": "nomatch"}},
	}
	lock := map[string]string{"x@1.0.0": "sha512-different"}
	findings := CrossReferenceSBOM(sbom, lock, "/sbom.json", false)
	found := false
	for _, f := range findings {
		if f.RuleID == "PROV-SBOM-003" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PROV-SBOM-003")
	}
}

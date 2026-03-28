package provenance

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// SBOMComponent represents a single component from an SBOM.
type SBOMComponent struct {
	Name    string
	Version string
	Hashes  map[string]string // algorithm -> hash value
}

// ParseCycloneDXBOM extracts components from a CycloneDX JSON SBOM.
func ParseCycloneDXBOM(data []byte) ([]SBOMComponent, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("cyclonedx: %w", err)
	}
	raw, ok := root["components"]
	if !ok {
		return nil, nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("cyclonedx components: %w", err)
	}
	var out []SBOMComponent
	for _, item := range items {
		var name, version string
		if v, ok := item["name"]; ok {
			if err := json.Unmarshal(v, &name); err != nil {
				continue
			}
		}
		if v, ok := item["version"]; ok {
			if err := json.Unmarshal(v, &version); err != nil {
				continue
			}
		}
		if name == "" || version == "" {
			continue
		}
		hashes := make(map[string]string)
		if rawH, ok := item["hashes"]; ok {
			var hashList []struct {
				Alg     string `json:"alg"`
				Content string `json:"content"`
			}
			if err := json.Unmarshal(rawH, &hashList); err == nil {
				for _, h := range hashList {
					a := strings.TrimSpace(h.Alg)
					c := strings.TrimSpace(h.Content)
					if a != "" && c != "" {
						hashes[strings.ToUpper(a)] = c
					}
				}
			}
		}
		out = append(out, SBOMComponent{Name: name, Version: version, Hashes: hashes})
	}
	return out, nil
}

// ParseSPDXBOM extracts packages from an SPDX JSON SBOM.
func ParseSPDXBOM(data []byte) ([]SBOMComponent, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("spdx: %w", err)
	}
	raw, ok := root["packages"]
	if !ok {
		return nil, nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("spdx packages: %w", err)
	}
	var out []SBOMComponent
	for _, item := range items {
		var name, version string
		if v, ok := item["name"]; ok {
			if err := json.Unmarshal(v, &name); err != nil {
				continue
			}
		}
		if v, ok := item["versionInfo"]; ok {
			if err := json.Unmarshal(v, &version); err != nil {
				continue
			}
		}
		if name == "" || version == "" {
			continue
		}
		hashes := make(map[string]string)
		if rawC, ok := item["checksums"]; ok {
			var chkList []struct {
				Algorithm     string `json:"algorithm"`
				ChecksumValue string `json:"checksumValue"`
			}
			if err := json.Unmarshal(rawC, &chkList); err == nil {
				for _, c := range chkList {
					a := strings.TrimSpace(c.Algorithm)
					vv := strings.TrimSpace(c.ChecksumValue)
					if a != "" && vv != "" {
						hashes[strings.ToUpper(a)] = vv
					}
				}
			}
		}
		out = append(out, SBOMComponent{Name: name, Version: version, Hashes: hashes})
	}
	return out, nil
}

// CrossReferenceSBOM compares SBOM components against lockfile hashes.
func CrossReferenceSBOM(sbomComponents []SBOMComponent, lockfileHashes map[string]string, sbomPath string, redact bool) []model.Finding {
	var findings []model.Finding
	sbomByKey := make(map[string]map[string]string)
	for _, c := range sbomComponents {
		key := c.Name + "@" + c.Version
		sbomByKey[key] = c.Hashes
	}
	for key := range sbomByKey {
		if _, ok := lockfileHashes[key]; !ok {
			findings = append(findings, model.Finding{
				RuleID:      "PROV-SBOM-001",
				Title:       "SBOM component not present in lockfiles",
				Description: fmt.Sprintf("Component %q appears in SBOM but has no matching lockfile entry.", key),
				Category:    "provenance",
				Mitre:       "T1195.002",
				Severity:    model.SeverityMedium,
				File:        sbomPath,
				Match:       security.SanitizeMatch("component="+key, redact),
			})
		}
	}
	for key, lockHash := range lockfileHashes {
		hashes, ok := sbomByKey[key]
		if !ok {
			findings = append(findings, model.Finding{
				RuleID:      "PROV-SBOM-002",
				Title:       "Lockfile package not declared in SBOM",
				Description: fmt.Sprintf("Package %q is pinned in a lockfile but missing from the SBOM.", key),
				Category:    "provenance",
				Mitre:       "T1195.002",
				Severity:    model.SeverityMedium,
				File:        sbomPath,
				Match:       security.SanitizeMatch("package="+key, redact),
			})
			continue
		}
		if len(hashes) == 0 {
			continue
		}
		if !lockMatchesSBOMHashes(lockHash, hashes) {
			findings = append(findings, model.Finding{
				RuleID:      "PROV-SBOM-003",
				Title:       "SBOM hash mismatch vs lockfile",
				Description: fmt.Sprintf("Integrity for %q does not match between SBOM and lockfile.", key),
				Category:    "provenance",
				Mitre:       "T1195.002",
				Severity:    model.SeverityHigh,
				File:        sbomPath,
				Match: security.SanitizeMatch(
					fmt.Sprintf("package=%s lock=%s", key, lockHash),
					redact,
				),
			})
		}
	}
	return findings
}

func lockMatchesSBOMHashes(lockHash string, sbomHashes map[string]string) bool {
	lockHash = strings.TrimSpace(lockHash)
	if lockHash == "" {
		return false
	}
	for _, v := range sbomHashes {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.EqualFold(lockHash, v) {
			return true
		}
		vLower := strings.ToLower(v)
		vHex := strings.TrimPrefix(vLower, "sha512:")
		vHex = strings.TrimPrefix(vHex, "sha384:")
		vHex = strings.TrimPrefix(vHex, "sha256:")
		if strings.HasPrefix(lockHash, "sha512-") {
			b64 := strings.TrimPrefix(lockHash, "sha512-")
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				raw, err = base64.RawStdEncoding.DecodeString(b64)
			}
			if err == nil {
				enc := hex.EncodeToString(raw)
				if strings.EqualFold(enc, vHex) {
					return true
				}
			}
		}
		if strings.HasPrefix(lockHash, "sha384-") {
			b64 := strings.TrimPrefix(lockHash, "sha384-")
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				raw, err = base64.RawStdEncoding.DecodeString(b64)
			}
			if err == nil {
				enc := hex.EncodeToString(raw)
				if strings.EqualFold(enc, vHex) {
					return true
				}
			}
		}
		if strings.HasPrefix(lockHash, "sha256-") {
			b64 := strings.TrimPrefix(lockHash, "sha256-")
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				raw, err = base64.RawStdEncoding.DecodeString(b64)
			}
			if err == nil {
				enc := hex.EncodeToString(raw)
				if strings.EqualFold(enc, vHex) {
					return true
				}
			}
		}
	}
	return false
}

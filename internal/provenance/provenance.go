package provenance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/TGPSKI/skeptic/internal/checks"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// ProvenanceManifest maps package names to expected integrity hashes.
type ProvenanceManifest map[string]string

// SignedProvenanceManifest extends ProvenanceManifest with optional signature fields.
type SignedProvenanceManifest struct {
	Packages  ProvenanceManifest `json:"packages"`
	Signature string             `json:"signature,omitempty"`
	PublicKey string             `json:"public_key,omitempty"`
}

// LoadProvenanceManifest reads a user-provided provenance manifest.
func LoadProvenanceManifest(path string) (ProvenanceManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest ProvenanceManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

// LoadSignedProvenanceManifest loads a manifest, supporting optional Ed25519 signatures.
// It unmarshals as SignedProvenanceManifest when a "packages" field is present; otherwise as a flat ProvenanceManifest.
// When requireSigned is true and no valid signature is present, findings include PROV-003.
// When a signature is present but verification fails, findings include PROV-004.
func LoadSignedProvenanceManifest(path string, requireSigned bool) (ProvenanceManifest, []model.Finding) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, []model.Finding{{
			RuleID:      "PROV-ERR",
			Title:       "Failed to load provenance manifest",
			Description: fmt.Sprintf("Could not read provenance manifest: %v", err),
			Category:    "provenance",
			Severity:    model.SeverityMedium,
			File:        path,
			Match:       err.Error(),
		}}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, []model.Finding{{
			RuleID:      "PROV-ERR",
			Title:       "Failed to parse provenance manifest",
			Description: fmt.Sprintf("Invalid JSON in provenance manifest: %v", err),
			Category:    "provenance",
			Severity:    model.SeverityMedium,
			File:        path,
			Match:       err.Error(),
		}}
	}
	var findings []model.Finding
	var manifest ProvenanceManifest
	if rawPkg, ok := top["packages"]; ok {
		var pkgMap ProvenanceManifest
		if err := json.Unmarshal(rawPkg, &pkgMap); err == nil {
			var signed SignedProvenanceManifest
			if err := json.Unmarshal(data, &signed); err != nil {
				return nil, []model.Finding{{
					RuleID:      "PROV-ERR",
					Title:       "Failed to parse signed provenance manifest",
					Description: fmt.Sprintf("Invalid signed manifest: %v", err),
					Category:    "provenance",
					Severity:    model.SeverityMedium,
					File:        path,
					Match:       err.Error(),
				}}
			}
			manifest = signed.Packages
			if requireSigned && strings.TrimSpace(signed.Signature) == "" {
				findings = append(findings, model.Finding{
					RuleID:      "PROV-003",
					Title:       "Signed provenance manifest required but missing signature",
					Description: "The manifest uses the signed wrapper format or --require-signed-manifest is set, but no signature was provided.",
					Category:    "provenance",
					Severity:    model.SeverityHigh,
					File:        path,
					Match:       "signature missing",
				})
			}
			if strings.TrimSpace(signed.Signature) != "" {
				if err := verifySignedManifestPackages(manifest, signed.PublicKey, signed.Signature); err != nil {
					findings = append(findings, model.Finding{
						RuleID:      "PROV-004",
						Title:       "Provenance manifest signature verification failed",
						Description: err.Error(),
						Category:    "provenance",
						Severity:    model.SeverityCritical,
						File:        path,
						Match:       security.SanitizeMatch(err.Error(), true),
					})
				}
			}
			return manifest, findings
		}
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, []model.Finding{{
			RuleID:      "PROV-ERR",
			Title:       "Failed to parse provenance manifest",
			Description: fmt.Sprintf("Invalid JSON in provenance manifest: %v", err),
			Category:    "provenance",
			Severity:    model.SeverityMedium,
			File:        path,
			Match:       err.Error(),
		}}
	}
	if requireSigned {
		findings = append(findings, model.Finding{
			RuleID:      "PROV-003",
			Title:       "Signed provenance manifest required but no signature present",
			Description: "Plain JSON manifest has no signature fields; use the signed manifest format with packages, signature, and public_key.",
			Category:    "provenance",
			Severity:    model.SeverityHigh,
			File:        path,
			Match:       "signature missing",
		})
	}
	return manifest, findings
}

func verifySignedManifestPackages(manifest ProvenanceManifest, pubEnc, sigEnc string) error {
	pubEnc = strings.TrimSpace(pubEnc)
	sigEnc = strings.TrimSpace(sigEnc)
	if pubEnc == "" {
		return fmt.Errorf("public_key is required when signature is present")
	}
	pubBytes, err := decodeFlexibleBytes(pubEnc)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key encoding")
	}
	pub := ed25519.PublicKey(pubBytes)
	sigBytes, err := decodeFlexibleBytes(sigEnc)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("invalid Ed25519 signature encoding")
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("cannot canonicalize packages for verification: %w", err)
	}
	if !ed25519.Verify(pub, payload, sigBytes) {
		return fmt.Errorf("Ed25519 verification failed for packages payload")
	}
	return nil
}

func decodeFlexibleBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	if len(s)%2 == 0 {
		if b, err := hex.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// RunProvenanceChecks compares lockfile hashes against a provenance manifest.
func RunProvenanceChecks(scanRoots []string, manifestPath string, requireSigned bool, redactSecrets bool, ignorePaths []string) []model.Finding {
	if strings.TrimSpace(manifestPath) == "" {
		return nil
	}
	manifest, loadFindings := LoadSignedProvenanceManifest(manifestPath, requireSigned)
	if manifest == nil {
		return loadFindings
	}
	findings := append([]model.Finding(nil), loadFindings...)

	allowed := map[string]bool{
		"gosum": true, "gomod": true, "npm": true,
		"cargo": true, "poetry": true, "pnpm": true, "yarn": true,
	}
	unionLockKeys := make(map[string]struct{})
	manifests := checks.DiscoverManifests(scanRoots, ignorePaths)
	for _, mf := range manifests {
		if !allowed[mf.Ecosystem] {
			continue
		}
		data, err := os.ReadFile(mf.Path)
		if err != nil {
			findings = append(findings, model.Finding{
				RuleID:      "PROV-ERR",
				Title:       "Failed to read lockfile",
				Description: fmt.Sprintf("Could not read lockfile: %v", err),
				Category:    "provenance",
				Severity:    model.SeverityMedium,
				File:        mf.Path,
				Match:       security.SanitizeMatch(err.Error(), redactSecrets),
			})
			continue
		}
		pkgHashes := ExtractPackageHashes(mf.Ecosystem, data)
		for pkg := range pkgHashes {
			unionLockKeys[pkg] = struct{}{}
		}
		for pkg, hash := range pkgHashes {
			expected, ok := manifest[pkg]
			if !ok {
				findings = append(findings, model.Finding{
					RuleID:      "PROV-002",
					Title:       "Package missing from provenance manifest",
					Description: fmt.Sprintf("Package %q found in lockfile but not in provenance manifest.", pkg),
					Category:    "provenance",
					Mitre:       "T1195.002",
					Severity:    model.SeverityMedium,
					File:        mf.Path,
					Match:       security.SanitizeMatch(fmt.Sprintf("package=%s", pkg), redactSecrets),
				})
				continue
			}
			if expected != hash {
				findings = append(findings, model.Finding{
					RuleID:      "PROV-001",
					Title:       "Provenance hash mismatch",
					Description: fmt.Sprintf("Package %q hash does not match provenance manifest.", pkg),
					Category:    "provenance",
					Mitre:       "T1195.002",
					Severity:    model.SeverityCritical,
					File:        mf.Path,
					Match:       security.SanitizeMatch(fmt.Sprintf("package=%s expected=%s actual=%s", pkg, expected, hash), redactSecrets),
				})
			}
		}
	}
	for pkg := range manifest {
		if _, ok := unionLockKeys[pkg]; !ok {
			findings = append(findings, model.Finding{
				RuleID:      "PROV-005",
				Title:       "Manifest entry with no corresponding lockfile package",
				Description: fmt.Sprintf("Package %q is listed in the provenance manifest but was not found in any scanned lockfile.", pkg),
				Category:    "provenance",
				Severity:    model.SeverityLow,
				File:        manifestPath,
				Match:       security.SanitizeMatch(fmt.Sprintf("package=%s", pkg), redactSecrets),
			})
		}
	}
	return findings
}

// ExtractPackageHashes pulls integrity hashes from lockfile content.
func ExtractPackageHashes(ecosystem string, data []byte) map[string]string {
	hashes := make(map[string]string)
	switch ecosystem {
	case "gosum":
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 || !strings.HasPrefix(fields[2], "h1:") {
				continue
			}
			key := fields[0] + "@" + fields[1]
			hashes[key] = fields[2]
		}
	case "gomod":
		return hashes
	case "npm":
		return ExtractNpmLockHashes(data)
	case "cargo":
		return ExtractCargoLockHashes(data)
	case "poetry":
		return ExtractPoetryLockHashes(data)
	case "pnpm":
		return ExtractPnpmLockHashes(data)
	case "yarn":
		return ExtractYarnLockHashes(data)
	}
	return hashes
}

// ExtractCargoLockHashes parses Cargo.lock for package checksums (line-based TOML-like blocks).
func ExtractCargoLockHashes(data []byte) map[string]string {
	hashes := make(map[string]string)
	var name, version, checksum string
	flush := func() {
		if name != "" && version != "" && checksum != "" {
			hashes[name+"@"+version] = checksum
		}
		name, version, checksum = "", "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			flush()
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			name = unquoteTOMLValue(strings.TrimPrefix(line, "name = "))
		}
		if strings.HasPrefix(line, "version = ") {
			version = unquoteTOMLValue(strings.TrimPrefix(line, "version = "))
		}
		if strings.HasPrefix(line, "checksum = ") {
			checksum = unquoteTOMLValue(strings.TrimPrefix(line, "checksum = "))
		}
	}
	flush()
	return hashes
}

// ExtractPoetryLockHashes parses poetry.lock for package hashes from [[package]] and [metadata.files].
func ExtractPoetryLockHashes(data []byte) map[string]string {
	lines := strings.Split(string(data), "\n")
	pkgVers := make(map[string]string)
	var curName, curVer string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[[package]]" {
			if curName != "" && curVer != "" {
				pkgVers[curName] = curVer
			}
			curName, curVer = "", ""
			continue
		}
		if strings.HasPrefix(line, "name = ") {
			curName = unquoteTOMLValue(strings.TrimPrefix(line, "name = "))
		}
		if strings.HasPrefix(line, "version = ") {
			curVer = unquoteTOMLValue(strings.TrimPrefix(line, "version = "))
		}
	}
	if curName != "" && curVer != "" {
		pkgVers[curName] = curVer
	}
	fileHashes := parsePoetryMetadataFiles(lines)
	out := make(map[string]string)
	for name, ver := range pkgVers {
		if h, ok := fileHashes[name]; ok && h != "" {
			out[name+"@"+ver] = h
		}
	}
	return out
}

func parsePoetryMetadataFiles(lines []string) map[string]string {
	out := make(map[string]string)
	inFiles := false
	var currentPkg string
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "[metadata.files]" {
			inFiles = true
			continue
		}
		if inFiles && strings.HasPrefix(t, "[") && t != "[metadata.files]" {
			break
		}
		if !inFiles {
			continue
		}
		if strings.HasSuffix(t, "= [") {
			idx := strings.Index(t, "=")
			if idx > 0 {
				currentPkg = strings.TrimSpace(t[:idx])
				currentPkg = strings.Trim(currentPkg, `"'`)
			}
			continue
		}
		if currentPkg != "" && strings.Contains(t, "hash") {
			h := extractHashFromPoetryLine(t)
			if h != "" {
				out[currentPkg] = h
				currentPkg = ""
			}
		}
		if t == "]" {
			currentPkg = ""
		}
	}
	return out
}

func extractHashFromPoetryLine(line string) string {
	// hash = "sha256:...." or hash = "..."
	idx := strings.Index(line, "hash")
	if idx < 0 {
		return ""
	}
	rest := line[idx+4:]
	start := strings.IndexAny(rest, `"'`)
	if start < 0 {
		return ""
	}
	q := rest[start]
	end := strings.Index(rest[start+1:], string(q))
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(rest[start+1 : start+1+end])
}

// ExtractPnpmLockHashes parses pnpm-lock.yaml for package integrity fields.
func ExtractPnpmLockHashes(data []byte) map[string]string {
	hashes := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "integrity:") {
			continue
		}
		val := extractIntegrityFieldValue(line)
		if val == "" {
			continue
		}
		for j := i - 1; j >= 0; j-- {
			prev := strings.TrimSpace(lines[j])
			if prev == "" || strings.HasPrefix(prev, "#") {
				continue
			}
			if !strings.HasSuffix(prev, ":") {
				continue
			}
			key := strings.TrimSuffix(prev, ":")
			key = strings.Trim(key, `"'`)
			if key == "resolution" || key == "dependencies" || key == "engines" || key == "peerDependencies" || key == "optionalDependencies" {
				continue
			}
			if k := pnpmKeyToNameVersion(key); k != "" {
				hashes[k] = val
				break
			}
		}
	}
	return hashes
}

func extractIntegrityFieldValue(line string) string {
	idx := strings.Index(line, "integrity:")
	if idx < 0 {
		return ""
	}
	val := strings.TrimSpace(line[idx+len("integrity:"):])
	val = strings.Trim(val, `"'`)
	val = strings.TrimSuffix(strings.TrimSpace(val), "}")
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "{") && strings.Contains(val, "integrity") {
		// resolution: {integrity: sha512-...}
		ii := strings.Index(val, "integrity")
		if ii >= 0 {
			sub := val[ii:]
			colon := strings.Index(sub, ":")
			if colon >= 0 {
				rest := strings.TrimSpace(sub[colon+1:])
				rest = strings.TrimSuffix(rest, "}")
				return strings.TrimSpace(strings.Trim(rest, `"'`))
			}
		}
	}
	return val
}

func pnpmKeyToNameVersion(key string) string {
	key = strings.TrimSpace(key)
	if key == "" || key == "packages" || key == "importers" || key == "snapshots" {
		return ""
	}
	if strings.HasPrefix(key, "/") {
		key = strings.TrimPrefix(key, "/")
		parts := strings.Split(key, "/")
		if len(parts) < 2 {
			return ""
		}
		ver := parts[len(parts)-1]
		name := strings.Join(parts[:len(parts)-1], "/")
		return name + "@" + ver
	}
	if strings.Contains(key, "@") {
		at := strings.LastIndex(key, "@")
		if at > 0 {
			name := key[:at]
			ver := key[at+1:]
			if name != "" && ver != "" {
				return name + "@" + ver
			}
		}
	}
	return ""
}

// ExtractYarnLockHashes parses classic yarn.lock for version and integrity lines.
func ExtractYarnLockHashes(data []byte) map[string]string {
	hashes := make(map[string]string)
	lines := strings.Split(string(data), "\n")
	var specKey, ver string
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(t, ":") {
			specKey = strings.TrimSuffix(t, ":")
			specKey = strings.Trim(specKey, `"'`)
			ver = ""
			continue
		}
		if strings.HasPrefix(t, "version ") {
			ver = unquoteTOMLValue(strings.TrimPrefix(t, "version "))
			continue
		}
		if strings.HasPrefix(t, "integrity ") {
			fields := strings.Fields(t)
			if len(fields) < 2 {
				continue
			}
			integ := fields[1]
			if specKey != "" && ver != "" {
				name := yarnSpecKeyToPackageName(specKey)
				if name != "" {
					hashes[name+"@"+ver] = integ
				}
			}
		}
	}
	return hashes
}

func yarnSpecKeyToPackageName(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	if spec[0] != '@' {
		i := strings.Index(spec, "@")
		if i <= 0 {
			return spec
		}
		return spec[:i]
	}
	rest := spec[1:]
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return spec
	}
	after := rest[slash+1:]
	at := strings.Index(after, "@")
	if at < 0 {
		return spec
	}
	return spec[:1+slash+1+at]
}

func unquoteTOMLValue(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, `"'`)
	return s
}

// ExtractNpmLockHashes reads package-lock.json v2/v3 "packages" entries with integrity (SRI).
func ExtractNpmLockHashes(data []byte) map[string]string {
	hashes := make(map[string]string)
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil {
		return hashes
	}
	rawPkgs, ok := root["packages"]
	if !ok {
		return hashes
	}
	var pkgs map[string]map[string]any
	if json.Unmarshal(rawPkgs, &pkgs) != nil {
		return hashes
	}
	for lockPath, meta := range pkgs {
		integ, _ := meta["integrity"].(string)
		ver, _ := meta["version"].(string)
		if integ == "" || ver == "" {
			continue
		}
		name, _ := meta["name"].(string)
		if name == "" {
			name = NpmPackageNameFromLockPath(lockPath)
		}
		if name == "" {
			continue
		}
		key := name + "@" + ver
		hashes[key] = integ
	}
	return hashes
}

// NpmPackageNameFromLockPath derives an npm package name from a package-lock "packages" key.
func NpmPackageNameFromLockPath(lockPath string) string {
	lockPath = strings.TrimPrefix(lockPath, "./")
	if lockPath == "" {
		return ""
	}
	const sep = "node_modules/"
	idx := strings.LastIndex(lockPath, sep)
	if idx >= 0 {
		return lockPath[idx+len(sep):]
	}
	if strings.HasPrefix(lockPath, "node_modules/") {
		return strings.TrimPrefix(lockPath, "node_modules/")
	}
	return lockPath
}

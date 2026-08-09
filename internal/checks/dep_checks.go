package checks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/pathfilter"
	"github.com/TGPSKI/skeptic/internal/security"
)

// PopularPackages contains top packages per ecosystem for typosquat detection.
var PopularPackages = map[string][]string{
	"npm": {
		"express", "react", "lodash", "axios", "typescript", "webpack", "chalk",
		"commander", "debug", "inquirer", "moment", "uuid", "dotenv", "eslint",
		"jest", "mocha", "prettier", "next", "vue", "angular",
	},
	"pypi": {
		"requests", "flask", "django", "numpy", "pandas", "boto3", "pytest",
		"setuptools", "pip", "pyyaml", "cryptography", "pillow", "scipy",
		"tensorflow", "torch", "scikit-learn", "celery", "redis", "sqlalchemy",
		"fastapi",
	},
	"go": {
		"fmt", "net", "http", "os", "io", "sync", "context", "crypto", "encoding",
		"github.com/gin-gonic/gin", "github.com/gorilla/mux",
		"github.com/stretchr/testify", "google.golang.org/grpc",
		"github.com/spf13/cobra", "github.com/spf13/viper",
	},
}

// RunDepChecks scans dependency manifests found during filesystem walk.
// ignorePaths carries the same --ignore-paths patterns internal/scan applies.
// This check walks the tree itself, so without them a caller who excluded a
// directory would still get DEP- findings from it.
func RunDepChecks(scanRoots []string, redactSecrets bool, ignorePaths []string) []model.Finding {
	var allFindings []model.Finding
	manifests := DiscoverManifests(scanRoots, ignorePaths)
	for _, mf := range manifests {
		findings := CheckManifest(mf.Path, mf.Ecosystem, redactSecrets)
		allFindings = append(allFindings, findings...)
	}
	allFindings = append(allFindings, CheckMissingLockfile(scanRoots, ignorePaths)...)
	return allFindings
}

// ManifestEntry is one discovered lockfile or manifest on disk.
type ManifestEntry struct {
	Path      string
	Ecosystem string
}

// DiscoverManifests walks each scan root for known lock/manifest filenames, skipping vendor-like dirs.
func DiscoverManifests(roots []string, ignorePaths []string) []ManifestEntry {
	var manifests []ManifestEntry
	manifestNames := map[string]string{
		"package-lock.json": "npm",
		"package.json":      "npm",
		"pnpm-lock.yaml":    "pnpm",
		"yarn.lock":         "yarn",
		"poetry.lock":       "poetry",
		"Pipfile.lock":      "pypi",
		"requirements.txt":  "pypi",
		"go.sum":            "gosum",
		"go.mod":            "gomod",
		"Cargo.lock":        "cargo",
	}
	for _, root := range roots {
		walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			relPath, relErr := filepath.Rel(root, path)
			if relErr != nil {
				relPath = path
			}
			if d.IsDir() {
				name := d.Name()
				if name == "node_modules" || name == "vendor" || name == ".git" || name == ".venv" {
					return filepath.SkipDir
				}
				if relPath != "." && pathfilter.Matches(relPath, ignorePaths) {
					return filepath.SkipDir
				}
				return nil
			}
			if pathfilter.Matches(relPath, ignorePaths) {
				return nil
			}
			if eco, ok := manifestNames[d.Name()]; ok {
				manifests = append(manifests, ManifestEntry{Path: path, Ecosystem: eco})
			}
			return nil
		})
		if walkErr != nil {
			fmt.Fprintf(os.Stderr, "dep_checks: walk error in %s: %v\n", root, walkErr)
		}
	}
	return manifests
}

// CheckManifest reads a manifest and runs ecosystem-specific checks (npm, PyPI, Go).
func CheckManifest(path string, ecosystem string, redactSecrets bool) []model.Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	fileLabel := path
	var findings []model.Finding

	switch ecosystem {
	case "npm":
		findings = append(findings, CheckNPMManifest(data, fileLabel, redactSecrets)...)
		findings = append(findings, CheckNPMLockfileIntegrity(data, fileLabel, redactSecrets)...)
	case "pnpm":
		findings = append(findings, checkPnpmManifest(data, fileLabel, redactSecrets)...)
	case "yarn":
		findings = append(findings, checkYarnManifest(data, fileLabel, redactSecrets)...)
	case "pypi":
		findings = append(findings, CheckPyPIManifest(data, fileLabel, redactSecrets)...)
	case "gosum":
		findings = append(findings, checkGoManifest(data, fileLabel, redactSecrets)...)
	case "gomod":
		findings = append(findings, checkGoModManifest(data, fileLabel, redactSecrets)...)
	}
	return findings
}

// CheckNPMManifest runs npm-oriented checks on package.json content.
func CheckNPMManifest(data []byte, fileLabel string, redact bool) []model.Finding {
	var findings []model.Finding
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}

	depSections := []string{"dependencies", "devDependencies", "optionalDependencies"}
	var allPkgNames []string
	for _, section := range depSections {
		raw, ok := parsed[section]
		if !ok {
			continue
		}
		var deps map[string]any
		if err := json.Unmarshal(raw, &deps); err != nil {
			continue
		}
		for name := range deps {
			allPkgNames = append(allPkgNames, name)
		}
	}

	for _, name := range allPkgNames {
		if IsSuspiciousTyposquat(name, "npm") {
			findings = append(findings, model.Finding{
				RuleID:          "DEP-002",
				ConfidenceClass: model.ConfidenceHeuristic,
				Title:           "Potential typosquat package name",
				Description:     fmt.Sprintf("Package %q has edit distance <= 2 from a popular npm package.", name),
				Category:        "dependency-check",
				Mitre:           "T1195.002",
				Severity:        model.SeverityHigh,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fmt.Sprintf("package=%s", name), redact),
			})
		}
	}

	if scriptsRaw, ok := parsed["scripts"]; ok {
		var scripts map[string]string
		if err := json.Unmarshal(scriptsRaw, &scripts); err == nil {
			for hook, cmd := range scripts {
				lowerHook := strings.ToLower(hook)
				if lowerHook == "preinstall" || lowerHook == "postinstall" || lowerHook == "prepare" {
					if strings.Contains(cmd, "curl") || strings.Contains(cmd, "wget") || strings.Contains(cmd, "node -e") {
						findings = append(findings, model.Finding{
							RuleID:          "DEP-004",
							ConfidenceClass: model.ConfidenceHeuristic,
							Title:           "Suspicious install hook command",
							Description:     fmt.Sprintf("Install hook %q executes: %s", hook, model.CompactSnippet(cmd)),
							Category:        "dependency-check",
							Mitre:           "T1195.002",
							Severity:        model.SeverityHigh,
							File:            fileLabel,
							Match:           security.SanitizeMatch(fmt.Sprintf("hook=%s cmd=%s", hook, model.CompactSnippet(cmd)), redact),
						})
					}
				}
			}
		}
	}

	return findings
}

// CheckNPMLockfileIntegrity validates npm package-lock.json for supply chain indicators.
func CheckNPMLockfileIntegrity(data []byte, fileLabel string, redact bool) []model.Finding {
	var findings []model.Finding
	if !strings.HasSuffix(fileLabel, "package-lock.json") {
		return nil
	}

	var lockfile struct {
		Packages map[string]struct {
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return []model.Finding{{
			RuleID:          "DEP-LOCK-ERR",
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           "npm lockfile parse error",
			Description:     fmt.Sprintf("Failed to parse %s: %v. The lockfile may be corrupted or malformed.", fileLabel, err),
			Category:        "dependency-check",
			Severity:        model.SeverityInfo,
			File:            fileLabel,
		}}
	}

	npmAllowed := []string{
		"registry.npmjs.org",
		"registry.npmjs.com",
		"registry.yarnpkg.com",
		"npm.pkg.github.com",
	}

	for name, pkg := range lockfile.Packages {
		if name == "" {
			continue
		}
		if pkg.Integrity == "" && pkg.Resolved != "" {
			findings = append(findings, model.Finding{
				RuleID:          "DEP-LOCK-001",
				ConfidenceClass: model.ConfidenceDefinitive,
				Title:           "npm lockfile dependency missing integrity hash",
				Description:     fmt.Sprintf("Package %q has a resolved URL but no integrity hash. Without an integrity field, npm cannot verify the tarball was not tampered with.", name),
				Category:        "dependency-check",
				Mitre:           "T1195.002",
				Severity:        model.SeverityHigh,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fmt.Sprintf("package=%s resolved=%s", name, model.CompactSnippet(pkg.Resolved)), redact),
			})
		}

		if pkg.Resolved != "" {
			u, err := url.Parse(pkg.Resolved)
			if err == nil && u.Host != "" {
				host := strings.ToLower(u.Hostname())
				isAllowed := false
				for _, h := range npmAllowed {
					if host == h {
						isAllowed = true
						break
					}
				}
				if !isAllowed && host != "" && !strings.HasSuffix(host, ".github.com") {
					findings = append(findings, model.Finding{
						RuleID:          "DEP-LOCK-002",
						ConfidenceClass: model.ConfidenceHeuristic,
						Title:           "npm lockfile resolved to non-default registry",
						Description:     fmt.Sprintf("Package %q resolves to %q which is not a standard npm registry. This may indicate dependency confusion or a compromised registry.", name, host),
						Category:        "dependency-check",
						Mitre:           "T1195.002",
						Severity:        model.SeverityHigh,
						File:            fileLabel,
						Match:           security.SanitizeMatch(fmt.Sprintf("package=%s host=%s", name, host), redact),
					})
				}
			}
		}
	}
	return findings
}

// CheckMissingLockfile detects manifest files without corresponding lockfiles in the same directory.
func CheckMissingLockfile(roots []string, ignorePaths []string) []model.Finding {
	var findings []model.Finding
	type manifestInfo struct {
		path      string
		ecosystem string
	}
	manifestsByDir := make(map[string][]manifestInfo)
	locksByDir := make(map[string]map[string]bool)

	npmLocks := map[string]bool{"package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true}
	pyLocks := map[string]bool{"uv.lock": true, "poetry.lock": true, "Pipfile.lock": true}

	for _, root := range roots {
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relPath, relErr := filepath.Rel(root, path)
			if relErr != nil {
				relPath = path
			}
			if d.IsDir() {
				name := d.Name()
				if name == "node_modules" || name == "vendor" || name == ".git" || name == ".venv" {
					return filepath.SkipDir
				}
				if relPath != "." && pathfilter.Matches(relPath, ignorePaths) {
					return filepath.SkipDir
				}
				return nil
			}
			if pathfilter.Matches(relPath, ignorePaths) {
				return nil
			}
			dir := filepath.Dir(path)
			name := d.Name()

			switch name {
			case "package.json":
				manifestsByDir[dir] = append(manifestsByDir[dir], manifestInfo{path, "npm"})
			case "requirements.txt", "pyproject.toml":
				manifestsByDir[dir] = append(manifestsByDir[dir], manifestInfo{path, "python"})
			}

			if locksByDir[dir] == nil {
				locksByDir[dir] = make(map[string]bool)
			}
			if npmLocks[name] {
				locksByDir[dir]["npm"] = true
			}
			if pyLocks[name] {
				locksByDir[dir]["python"] = true
			}
			return nil
		}); err != nil {
			findings = append(findings, model.Finding{
				RuleID:          "DEP-LOCK-ERR",
				ConfidenceClass: model.ConfidenceDefinitive,
				Title:           "lockfile discovery walk error",
				Description:     fmt.Sprintf("Failed to walk %s for lockfile discovery: %v", root, err),
				Category:        "dependency-check",
				Severity:        model.SeverityInfo,
				File:            root,
			})
		}
	}

	for dir, manifests := range manifestsByDir {
		locks := locksByDir[dir]
		for _, m := range manifests {
			if m.ecosystem == "npm" && !locks["npm"] {
				findings = append(findings, model.Finding{
					RuleID:          "DEP-LOCK-003",
					ConfidenceClass: model.ConfidenceHeuristic,
					Title:           "Package manifest without lockfile",
					Description:     fmt.Sprintf("package.json exists at %s without a corresponding package-lock.json, pnpm-lock.yaml, or yarn.lock. Installs are non-deterministic and vulnerable to supply chain substitution.", m.path),
					Category:        "dependency-check",
					Mitre:           "T1195.002",
					Severity:        model.SeverityMedium,
					File:            m.path,
				})
			}
			if m.ecosystem == "python" && !locks["python"] {
				findings = append(findings, model.Finding{
					RuleID:          "DEP-LOCK-004",
					ConfidenceClass: model.ConfidenceHeuristic,
					Title:           "Python manifest without lockfile",
					Description:     fmt.Sprintf("Python manifest exists at %s without a corresponding uv.lock, poetry.lock, or Pipfile.lock. Installs are non-deterministic.", m.path),
					Category:        "dependency-check",
					Mitre:           "T1195.002",
					Severity:        model.SeverityMedium,
					File:            m.path,
				})
			}
		}
	}
	return findings
}

// CheckPyPIManifest runs PyPI-oriented checks on requirements-style content.
func CheckPyPIManifest(data []byte, fileLabel string, redact bool) []model.Finding {
	var findings []model.Finding
	content := string(data)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parts := strings.FieldsFunc(trimmed, func(r rune) bool {
			return r == '=' || r == '>' || r == '<' || r == '!' || r == '~' || r == ';' || r == '[' || r == ' '
		})
		if len(parts) == 0 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "" || strings.HasPrefix(name, "-") {
			continue
		}
		if IsSuspiciousTyposquat(name, "pypi") {
			findings = append(findings, model.Finding{
				RuleID:          "DEP-002",
				ConfidenceClass: model.ConfidenceHeuristic,
				Title:           "Potential typosquat package name",
				Description:     fmt.Sprintf("Package %q has edit distance <= 2 from a popular PyPI package.", name),
				Category:        "dependency-check",
				Mitre:           "T1195.002",
				Severity:        model.SeverityHigh,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fmt.Sprintf("package=%s", name), redact),
			})
		}
	}
	return findings
}

func checkPnpmManifest(data []byte, fileLabel string, redact bool) []model.Finding {
	var findings []model.Finding
	pnpmSkipKeys := map[string]bool{
		"dependencies": true, "devdependencies": true, "optionaldependencies": true,
		"peerdependencies": true, "patcheddependencies": true, "specifiers": true,
		"importers": true, "packages": true, "settings": true, "lockfileversion": true,
		"overrides": true, "neverbuiltdependencies": true,
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "/") || (strings.Contains(t, "/") && strings.HasSuffix(t, ":")) {
			key := strings.TrimSuffix(t, ":")
			key = strings.Trim(key, `"'`)
			if strings.HasPrefix(key, "/") {
				rest := strings.TrimPrefix(key, "/")
				lastAt := strings.LastIndex(rest, "@")
				if lastAt > 0 {
					pkgName := rest[:lastAt]
					if pkgName != "" && IsSuspiciousTyposquat(pkgName, "npm") {
						findings = append(findings, model.Finding{
							RuleID:          "DEP-002",
							ConfidenceClass: model.ConfidenceHeuristic,
							Title:           "Potential typosquat package name",
							Description:     fmt.Sprintf("Package %q in pnpm lockfile is edit-distance close to a popular npm package.", pkgName),
							Category:        "dependency-check",
							Mitre:           "T1195.002",
							Severity:        model.SeverityHigh,
							File:            fileLabel,
							Match:           security.SanitizeMatch(fmt.Sprintf("package=%s", pkgName), redact),
						})
					}
				}
			}
			continue
		}
		if !strings.Contains(t, ":") {
			continue
		}
		colon := strings.Index(t, ":")
		if colon <= 0 {
			continue
		}
		name := strings.TrimSpace(t[:colon])
		if name == "" || strings.Contains(name, " ") {
			continue
		}
		low := strings.ToLower(name)
		if pnpmSkipKeys[low] {
			continue
		}
		if !strings.ContainsAny(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-") {
			continue
		}
		if IsSuspiciousTyposquat(name, "npm") {
			findings = append(findings, model.Finding{
				RuleID:          "DEP-002",
				ConfidenceClass: model.ConfidenceHeuristic,
				Title:           "Potential typosquat package name",
				Description:     fmt.Sprintf("Package %q in pnpm lockfile is edit-distance close to a popular npm package.", name),
				Category:        "dependency-check",
				Mitre:           "T1195.002",
				Severity:        model.SeverityHigh,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fmt.Sprintf("package=%s", name), redact),
			})
		}
	}
	return findings
}

func checkYarnManifest(data []byte, fileLabel string, redact bool) []model.Finding {
	var findings []model.Finding
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if strings.HasPrefix(t, "resolved ") {
				raw := parseYarnResolvedURL(t)
				if raw != "" && !yarnResolvedRegistryOK(raw) {
					findings = append(findings, model.Finding{
						RuleID:          "DEP-005",
						ConfidenceClass: model.ConfidenceHeuristic,
						Title:           "Unexpected yarn resolved registry URL",
						Description:     fmt.Sprintf("resolved URL %q does not match common npm/yarn/GitHub registry hosts.", model.CompactSnippet(raw)),
						Category:        "dependency-check",
						Mitre:           "T1195.002",
						Severity:        model.SeverityHigh,
						File:            fileLabel,
						Match:           security.SanitizeMatch(fmt.Sprintf("resolved=%s", model.CompactSnippet(raw)), redact),
					})
				}
			}
			continue
		}
		if !strings.HasSuffix(t, ":") || !strings.Contains(t, "@") {
			continue
		}
		key := strings.TrimSuffix(t, ":")
		key = strings.Trim(key, `"'`)
		pkgName := yarnPackageNameFromKey(key)
		if pkgName == "" {
			continue
		}
		if IsSuspiciousTyposquat(pkgName, "npm") {
			findings = append(findings, model.Finding{
				RuleID:          "DEP-002",
				ConfidenceClass: model.ConfidenceHeuristic,
				Title:           "Potential typosquat package name",
				Description:     fmt.Sprintf("Package %q in yarn.lock is edit-distance close to a popular npm package.", pkgName),
				Category:        "dependency-check",
				Mitre:           "T1195.002",
				Severity:        model.SeverityHigh,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fmt.Sprintf("package=%s", pkgName), redact),
			})
		}
	}
	return findings
}

func yarnPackageNameFromKey(key string) string {
	lastAt := strings.LastIndex(key, "@")
	if lastAt <= 0 {
		return ""
	}
	return key[:lastAt]
}

func parseYarnResolvedURL(line string) string {
	if !strings.HasPrefix(line, "resolved ") {
		return ""
	}
	rest := strings.TrimSpace(line[len("resolved "):])
	if len(rest) >= 2 && rest[0] == '"' {
		if end := strings.Index(rest[1:], `"`); end >= 0 {
			return rest[1 : end+1]
		}
		return ""
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func yarnResolvedRegistryOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	allowed := []string{
		"registry.npmjs.org",
		"registry.yarnpkg.com",
		"registry.npmjs.com",
		"npm.pkg.github.com",
		"registry.npmmirror.com",
		"codeload.github.com",
		"raw.githubusercontent.com",
	}
	for _, h := range allowed {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	if host == "github.com" || strings.HasSuffix(host, ".github.com") {
		return true
	}
	return false
}

// validGoSumH1 reports whether an h1: value looks like a valid go.sum SHA-256 checksum (base64, 32 bytes).
func validGoSumH1(hash string) bool {
	hash = strings.TrimSpace(hash)
	if len(hash) < 40 {
		return false
	}
	dec, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		dec, err = base64.RawStdEncoding.DecodeString(hash)
	}
	if err != nil {
		return false
	}
	return len(dec) == 32
}

// checkGoManifest flags modules in go.sum that list more than one registry host for the same import path.
func checkGoManifest(data []byte, fileLabel string, redact bool) []model.Finding {
	var findings []model.Finding
	content := string(data)
	lines := strings.Split(content, "\n")
	registries := make(map[string]map[string]bool) // pkg -> set of registry hosts
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, f := range fields {
			if strings.HasPrefix(f, "h1:") {
				h := strings.TrimPrefix(f, "h1:")
				if !validGoSumH1(h) {
					findings = append(findings, model.Finding{
						RuleID:          "DEP-HASH-001",
						ConfidenceClass: model.ConfidenceHeuristic,
						Title:           "Invalid go.sum h1 hash format",
						Description:     fmt.Sprintf("h1 checksum %q does not look like a valid base64-encoded SHA-256 sum.", model.CompactSnippet(h)),
						Category:        "dependency-check",
						Mitre:           "T1195.002",
						Severity:        model.SeverityHigh,
						File:            fileLabel,
						Match:           security.SanitizeMatch(fmt.Sprintf("h1=%s", model.CompactSnippet(h)), redact),
					})
				}
			}
		}
		pkgPath := fields[0]
		parts := strings.SplitN(pkgPath, "/", 2)
		if len(parts) < 2 {
			continue
		}
		host := parts[0]
		if registries[pkgPath] == nil {
			registries[pkgPath] = make(map[string]bool)
		}
		registries[pkgPath][host] = true
	}
	for pkg, hosts := range registries {
		if len(hosts) > 1 {
			hostList := make([]string, 0, len(hosts))
			for h := range hosts {
				hostList = append(hostList, h)
			}
			findings = append(findings, model.Finding{
				RuleID:          "DEP-001",
				ConfidenceClass: model.ConfidenceHeuristic,
				Title:           "Multiple registry sources for same package",
				Description:     fmt.Sprintf("Package %q resolves from multiple registries: %s", pkg, strings.Join(hostList, ", ")),
				Category:        "dependency-check",
				Mitre:           "T1195.002",
				Severity:        model.SeverityCritical,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fmt.Sprintf("package=%s registries=%s", pkg, strings.Join(hostList, ",")), redact),
			})
		}
	}
	return findings
}

// checkGoModManifest parses go.mod files, extracting module paths from require
// blocks and checking them for typosquatting / multi-registry patterns.
func checkGoModManifest(data []byte, fileLabel string, redact bool) []model.Finding {
	var findings []model.Finding
	lines := strings.Split(string(data), "\n")
	inRequire := false
	registries := make(map[string]map[string]bool)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "require (" {
			inRequire = true
			continue
		}
		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}
		var modPath string
		if inRequire {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				modPath = fields[0]
			}
		} else if strings.HasPrefix(trimmed, "require ") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 3 {
				modPath = fields[1]
			}
		}
		if modPath == "" || strings.HasPrefix(modPath, "//") {
			continue
		}
		parts := strings.SplitN(modPath, "/", 2)
		host := parts[0]
		if registries[modPath] == nil {
			registries[modPath] = make(map[string]bool)
		}
		registries[modPath][host] = true

		if isSuspiciousGoModuleTyposquat(modPath) {
			findings = append(findings, model.Finding{
				RuleID:          "DEP-TYPO-001",
				ConfidenceClass: model.ConfidenceHeuristic,
				Title:           "Possible typosquat dependency",
				Description:     fmt.Sprintf("Go module %q is edit-distance close to a popular module (ratio-based full-path comparison)", modPath),
				Category:        "dependency-check",
				Mitre:           "T1195.002",
				Severity:        model.SeverityHigh,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fmt.Sprintf("module=%s", modPath), redact),
			})
		}
	}
	for pkg, hosts := range registries {
		if len(hosts) > 1 {
			hostList := make([]string, 0, len(hosts))
			for h := range hosts {
				hostList = append(hostList, h)
			}
			findings = append(findings, model.Finding{
				RuleID:          "DEP-001",
				ConfidenceClass: model.ConfidenceHeuristic,
				Title:           "Multiple registry sources for same package",
				Description:     fmt.Sprintf("Go module %q resolves from multiple registries: %s", pkg, strings.Join(hostList, ", ")),
				Category:        "dependency-check",
				Mitre:           "T1195.002",
				Severity:        model.SeverityCritical,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fmt.Sprintf("module=%s registries=%s", pkg, strings.Join(hostList, ",")), redact),
			})
		}
	}
	return findings
}

// IsSuspiciousTyposquat checks if a package name is suspiciously close to a
// popular package using ratio-based edit distance. Short names (< 5 chars) are
// excluded to avoid false positives on legitimate short package names. The ratio
// threshold (distance / max_length <= 0.3) scales with name length.
func IsSuspiciousTyposquat(name string, ecosystem string) bool {
	popular, ok := PopularPackages[ecosystem]
	if !ok {
		return false
	}
	lower := strings.ToLower(name)
	if len(lower) < 5 {
		return false
	}
	for _, pkg := range popular {
		pkgLower := strings.ToLower(pkg)
		if lower == pkgLower {
			return false
		}
		dist := EditDistance(lower, pkgLower)
		if dist == 0 || dist > 2 {
			continue
		}
		maxLen := len(lower)
		if len(pkgLower) > maxLen {
			maxLen = len(pkgLower)
		}
		if maxLen > 0 && float64(dist)/float64(maxLen) <= 0.3 {
			return true
		}
	}
	return false
}

// isSuspiciousGoModuleTyposquat compares full Go module paths against the
// popular modules list using ratio-based edit distance (threshold 0.25).
// Unlike the npm/PyPI check, this compares the full canonical path instead
// of stripping to the last segment, avoiding false positives from short
// last-segment names like "mux" or "gin".
func isSuspiciousGoModuleTyposquat(modPath string) bool {
	popular, ok := PopularPackages["go"]
	if !ok {
		return false
	}
	lower := strings.ToLower(modPath)
	for _, pkg := range popular {
		pkgLower := strings.ToLower(pkg)
		if lower == pkgLower {
			return false
		}
		if !strings.Contains(pkgLower, "/") {
			continue
		}
		dist := EditDistance(lower, pkgLower)
		if dist == 0 || dist > 2 {
			continue
		}
		maxLen := len(lower)
		if len(pkgLower) > maxLen {
			maxLen = len(pkgLower)
		}
		if maxLen > 0 && float64(dist)/float64(maxLen) <= 0.25 {
			return true
		}
	}
	return false
}

// EditDistance computes Levenshtein distance between two strings.
func EditDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = MinInt(MinInt(prev[j]+1, curr[j-1]+1), prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

// MinInt returns the smaller of two ints.
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

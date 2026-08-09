package scan

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/pathfilter"
	"github.com/TGPSKI/skeptic/internal/security"
)

var repoSkipDirs = map[string]struct{}{
	".git":         {},
	".hg":          {},
	".svn":         {},
	"node_modules": {},
	"vendor":       {},
	".venv":        {},
	"venv":         {},
	".tox":         {},
	"dist":         {},
	"build":        {},
	"out":          {},
	".idea":        {},
	".cursor":      {},
	".cache":       {},
	"rulepacks":    {},
}

// cacheArtifactDirs are build/tool cache directories that get skipped for
// content scanning but emit a supply-chain finding when present in a repo.
// Committed cache dirs are a hygiene smell and can conceal tampered artifacts.
var cacheArtifactDirs = map[string]struct{}{
	".pytest_cache": {},
	".mypy_cache":   {},
	"__pycache__":   {},
	".ruff_cache":   {},
}

var fullFSSkipDirs = map[string]struct{}{
	"proc":       {},
	"sys":        {},
	"dev":        {},
	"run":        {},
	"mnt":        {},
	"media":      {},
	"lost+found": {},
}

var sensitiveSymlinkTargets = regexp.MustCompile(
	`(?i)(^|/)(\.ssh|\.aws|\.gnupg|\.config/gcloud|\.azure|\.docker|` +
		`\.cursor|\.vscode|\.git/|etc/shadow|etc/passwd|` +
		`var/run/secrets|proc/self)(/|$)`,
)

var swapBackupPattern = regexp.MustCompile(
	`(?i)(\.swp|\.swo|\.swn|~|\.bak|\.orig|\.save|\.tmp|\.temp|\.old|\.DS_Store|Thumbs\.db|desktop\.ini)$`,
)

var envFilePattern = regexp.MustCompile(
	`(?i)(^|/)\.env(\.(local|development|staging|production|test|example))?$`,
)

var binaryMetadataPattern = regexp.MustCompile(`(?i)(\.DS_Store|Thumbs\.db)$`)
var textMetadataPattern = regexp.MustCompile(`(?i)(desktop\.ini)$`)

// matchesIgnorePath delegates to pathfilter so this walker and the
// identity-graph walker in internal/checks share one definition of "ignored".
func matchesIgnorePath(relPath string, patterns []string) bool {
	return pathfilter.Matches(relPath, patterns)
}

func walkDirEntry(
	path string,
	d fs.DirEntry,
	wErr error,
	root string,
	opts model.ScanOptions,
	stateCache *IncrementalStateCache,
	report *model.Report,
	useAbsolutePaths bool,
	enqueueTask func(scanTask) error,
) error {
	if wErr != nil {
		if os.IsPermission(wErr) && opts.IgnorePermissionErrors {
			report.PermissionErrors++
			report.SkippedFiles++
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		return wErr
	}

	if d.Type()&os.ModeSymlink != 0 {
		emitSymlinkFindings(path, root, report)
		return nil
	}

	if d.IsDir() {
		if path == root {
			return nil
		}
		if len(opts.IgnorePaths) > 0 {
			relPath := toRelativeSlash(root, path)
			if matchesIgnorePath(relPath, opts.IgnorePaths) {
				return filepath.SkipDir
			}
		}
		if isCacheArtifactDir(d.Name()) {
			report.Findings = append(report.Findings, model.Finding{
				RuleID:          "SCM-CACHE-001",
				Title:           "Committed build/tool cache directory",
				Description:     "Build or tool cache directory is present in the repository tree. Committed caches can conceal tampered bytecode, serialized AST data, or poisoned type stubs and indicate weak .gitignore hygiene.",
				Category:        "supply-chain",
				Mitre:           "T1195.002",
				Severity:        model.SeverityMedium,
				File:            toRelativeSlash(root, path),
				Match:           d.Name(),
				ConfidenceClass: model.DefaultConfidenceForRuleID("SCM-CACHE-001"),
			})
			return filepath.SkipDir
		}
		if shouldSkipDir(opts.Profile, d.Name()) {
			return filepath.SkipDir
		}
		if hasCorpusMarker(path) {
			return filepath.SkipDir
		}
		return nil
	}

	if !d.Type().IsRegular() {
		return nil
	}

	emitResidualArtifactFindings(path, root, d.Name(), report)

	if stateCache.Enabled() && filepath.Clean(path) == filepath.Clean(stateCache.Path()) {
		report.SkippedFiles++
		return nil
	}

	dInfo, infoErr := d.Info()
	if infoErr != nil {
		if os.IsPermission(infoErr) && opts.IgnorePermissionErrors {
			report.PermissionErrors++
			report.SkippedFiles++
			return nil
		}
		return infoErr
	}
	shouldScan := true
	if stateCache.Enabled() {
		shouldScan, infoErr = stateCache.ShouldScan(path, dInfo)
		if infoErr != nil {
			return infoErr
		}
	}
	if !shouldScan {
		report.SkippedFiles++
		report.CacheSkippedFiles++
		return nil
	}

	if len(opts.IgnorePaths) > 0 {
		relPath := toRelativeSlash(root, path)
		if matchesIgnorePath(relPath, opts.IgnorePaths) {
			report.SkippedFiles++
			return nil
		}
	}

	enqErr := enqueueTask(scanTask{
		path:            path,
		root:            root,
		useAbsolutePath: useAbsolutePaths,
	})
	if enqErr != nil {
		opts.Logger.Warnf("enqueue halted at %s: %v", path, enqErr)
		return enqErr
	}
	return nil
}

//nolint:gocyclo // directory traversal with many skip conditions
func walkAndEnqueue(
	ctx context.Context,
	opts model.ScanOptions,
	stateCache *IncrementalStateCache,
	report *model.Report,
	jobs chan<- scanTask,
	results <-chan scanResult,
	applyResult func(scanResult),
) (walkComplete bool, walkErr error) {
	queuedFiles := 0
	enqueueTask := func(task scanTask) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if opts.MaxFiles > 0 && queuedFiles >= opts.MaxFiles {
			report.MaxFilesReached = true
			return errMaxFilesReached
		}
		queuedFiles++
		for {
			select {
			case jobs <- task:
				return nil
			case result, ok := <-results:
				if !ok {
					return errors.New("scan workers stopped unexpectedly")
				}
				applyResult(result)
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	walkComplete = true
	for _, root := range opts.Paths {
		if ctx.Err() != nil {
			walkComplete = false
			walkErr = ctx.Err()
			break
		}
		opts.Logger.Debugf("walking root: %s", root)
		info, statErr := os.Stat(root)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				report.SkippedFiles++
				continue
			}
			if os.IsPermission(statErr) && opts.IgnorePermissionErrors {
				report.PermissionErrors++
				report.SkippedFiles++
				continue
			}
			walkErr = statErr
			break
		}

		useAbsolutePaths := len(opts.Paths) > 1 || opts.Profile != model.ProfileRepo || root == "/"
		if info.Mode().IsRegular() {
			if stateCache.Enabled() && filepath.Clean(root) == filepath.Clean(stateCache.Path()) {
				report.SkippedFiles++
				continue
			}
			shouldScan := true
			var cacheErr error
			if stateCache.Enabled() {
				shouldScan, cacheErr = stateCache.ShouldScan(root, info)
				if cacheErr != nil {
					walkErr = cacheErr
					break
				}
			}
			if !shouldScan {
				report.SkippedFiles++
				report.CacheSkippedFiles++
				continue
			}
			if len(opts.IgnorePaths) > 0 {
				ignoreRel := filepath.ToSlash(filepath.Base(root))
				if matchesIgnorePath(ignoreRel, opts.IgnorePaths) {
					report.SkippedFiles++
					continue
				}
			}
			if enqErr := enqueueTask(scanTask{
				path:            root,
				root:            filepath.Dir(root),
				useAbsolutePath: useAbsolutePaths,
			}); enqErr != nil {
				if errors.Is(enqErr, errMaxFilesReached) {
					break
				}
				walkErr = enqErr
				break
			}
			continue
		}
		if !info.IsDir() {
			report.SkippedFiles++
			continue
		}

		rootWalkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, wErr error) error {
			return walkDirEntry(path, d, wErr, root, opts, stateCache, report, useAbsolutePaths, enqueueTask)
		})
		if rootWalkErr != nil {
			if errors.Is(rootWalkErr, errMaxFilesReached) {
				report.MaxFilesReached = true
				rootWalkErr = nil
				walkComplete = false
			}
			if rootWalkErr != nil {
				walkErr = rootWalkErr
				walkComplete = false
				break
			}
		}
	}
	if walkErr != nil {
		walkComplete = false
	}
	return walkComplete, walkErr
}

func emitSymlinkFindings(path, root string, report *model.Report) {
	relPath := toRelativeSlash(root, path)
	target, err := os.Readlink(path)
	if err != nil {
		return
	}

	symlinkSeverity := model.SeverityMedium
	symlinkDesc := "Committed symlink in repository. Even relative symlinks redirect agent file access: an agent reading this path gets content from the target instead. Review that the symlink target is intentional and hasn't been altered."
	if filepath.IsAbs(target) {
		symlinkSeverity = model.SeverityHigh
		symlinkDesc = "Committed symlink with absolute target path. Absolute symlinks redirect file access to a fixed system location, which agents and build tools follow without question."
	}
	report.Findings = append(report.Findings, model.Finding{
		RuleID:      "SCM-SYM-001",
		Title:       "Committed symlink in repository",
		Description: symlinkDesc,
		Category:    "non-code-surface",
		Mitre:       "T1027",
		Severity:    symlinkSeverity,
		File:        relPath,
		Match:       fmt.Sprintf("target=%s", target),
	})

	resolved, resolveErr := filepath.EvalSymlinks(path)
	absRoot, absErr := filepath.Abs(root)
	if resolveErr == nil && absErr == nil && absRoot != "" {
		rootPrefix := absRoot + string(filepath.Separator)
		if resolved != absRoot && !strings.HasPrefix(resolved, rootPrefix) {
			report.Findings = append(report.Findings, model.Finding{
				RuleID:          "SCM-SYM-002",
				Title:           "Symlink escapes repository root",
				Description:     "Symbolic link resolves to a path outside the repository root. This can be used to access sensitive host files, escape build sandboxes, or redirect agent file operations to unintended locations.",
				Category:        "non-code-surface",
				Mitre:           "T1083",
				Severity:        model.SeverityHigh,
				File:            relPath,
				Match:           fmt.Sprintf("target=%s resolved=%s", target, resolved),
				ConfidenceClass: model.ConfidenceDefinitive,
			})
		}
	}

	if sensitiveSymlinkTargets.MatchString(target) {
		report.Findings = append(report.Findings, model.Finding{
			RuleID:          "SCM-SYM-003",
			Title:           "Symlink targets sensitive path",
			Description:     "Symbolic link targets a high-value credential, configuration, or system path. Committed symlinks to .ssh, .aws, .git internals, or /etc can expose secrets to build tools and agents.",
			Category:        "non-code-surface",
			Mitre:           "T1552.001",
			Severity:        model.SeverityCritical,
			File:            relPath,
			Match:           fmt.Sprintf("target=%s", target),
			ConfidenceClass: model.ConfidenceDefinitive,
		})
	}
}

func emitResidualArtifactFindings(path, root, name string, report *model.Report) {
	relPath := toRelativeSlash(root, path)

	if swapBackupPattern.MatchString(name) {
		severity := model.SeverityMedium
		desc := "Editor backup file committed. These files are invisible to normal review but may be ingested by AI agents as project context. They can contain pre-redacted credentials, partial secrets, or injected instructions."
		if binaryMetadataPattern.MatchString(name) {
			severity = model.SeverityLow
			desc = "Binary OS metadata file committed (.DS_Store/Thumbs.db). While binary and unable to contain text injection, their presence signals the repository lacks gitignore discipline — other invisible files may also be committed."
		} else if textMetadataPattern.MatchString(name) {
			desc = "Text-based OS metadata file committed (desktop.ini). Nobody reviews these files but agents may ingest them. Their presence in a git repository is already unusual; check for injected content."
		}
		report.Findings = append(report.Findings, model.Finding{
			RuleID:          "SCM-TEMP-001",
			Title:           "Editor swap/backup file committed",
			Description:     desc,
			Category:        "non-code-surface",
			Mitre:           "T1552.004",
			Severity:        severity,
			File:            relPath,
			Match:           name,
			ConfidenceClass: model.ConfidenceDefinitive,
		})
	}

	if envFilePattern.MatchString(relPath) {
		sev := model.SeverityHigh
		if strings.HasSuffix(strings.ToLower(name), ".example") {
			sev = model.SeverityInfo
		}
		report.Findings = append(report.Findings, model.Finding{
			RuleID:          "SCM-TEMP-002",
			Title:           "Environment file committed to repository",
			Description:     "A .env file is committed to the repository. Environment files typically contain secrets, API keys, database credentials, and other sensitive configuration that should not be version controlled.",
			Category:        "non-code-surface",
			Mitre:           "T1552.001",
			Severity:        sev,
			File:            relPath,
			Match:           name,
			ConfidenceClass: model.DefaultConfidenceForRuleID("SCM-TEMP-002"),
		})
	}
}

// countEligibleFiles does a fast stat-only walk to estimate the number of
// files that will be scanned. It uses the same directory-skip and size-limit
// logic as the real scan but does not read file contents.
func countEligibleFiles(opts model.ScanOptions, stateCache *IncrementalStateCache) int {
	count := 0
	for _, root := range opts.Paths {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if info.Mode().IsRegular() {
			if info.Size() <= opts.MaxBytes {
				count++
			}
			continue
		}
		if !info.IsDir() {
			continue
		}
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, wErr error) error {
			if wErr != nil {
				if os.IsPermission(wErr) && opts.IgnorePermissionErrors {
					if d != nil && d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				return wErr
			}
			if d.IsDir() {
				if path != root && shouldSkipDir(opts.Profile, d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if stateCache != nil && stateCache.Enabled() && filepath.Clean(path) == filepath.Clean(stateCache.Path()) {
				return nil
			}
			dInfo, infoErr := d.Info()
			if infoErr != nil {
				return nil
			}
			if dInfo.Size() > opts.MaxBytes {
				return nil
			}
			if stateCache != nil && stateCache.Enabled() {
				shouldScan, cacheErr := stateCache.ShouldScan(path, dInfo)
				if cacheErr != nil || !shouldScan {
					return nil
				}
			}
			if opts.MaxFiles > 0 && count >= opts.MaxFiles {
				return errMaxFilesReached
			}
			count++
			return nil
		})
		if walkErr != nil && opts.Logger != nil {
			opts.Logger.Warnf("walk error estimating file count for %s: %v", root, walkErr)
		}
	}
	return count
}

func shouldSkipDir(profile model.ScanProfile, name string) bool {
	if _, skip := repoSkipDirs[name]; skip {
		return true
	}
	if _, skip := cacheArtifactDirs[name]; skip {
		return true
	}
	if profile == model.ProfileContainer || profile == model.ProfileFullFS {
		if _, skip := fullFSSkipDirs[name]; skip {
			return true
		}
	}
	return false
}

func isCacheArtifactDir(name string) bool {
	_, ok := cacheArtifactDirs[name]
	return ok
}

// hasCorpusMarker checks if a directory contains the .skeptic-corpus-lock marker file,
// indicating it is a corpus directory that should be skipped during normal scans.
func hasCorpusMarker(dirPath string) bool {
	_, err := os.Stat(filepath.Join(dirPath, ".skeptic-corpus-lock"))
	return err == nil
}

func toRelativeSlash(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}

// ShouldSkipDir applies profile-specific directory skip policy.
func ShouldSkipDir(profile model.ScanProfile, name string) bool {
	return shouldSkipDir(profile, name)
}

// WorldWritableArtifactFinding raises hardening findings for mutable scanner-critical artifacts.
func WorldWritableArtifactFinding(absPath, fileLabel string, info os.FileInfo, redactSecrets bool) (model.Finding, bool) {
	return worldWritableArtifactFinding(absPath, fileLabel, info, redactSecrets)
}

func worldWritableArtifactFinding(absPath string, fileLabel string, info os.FileInfo, redactSecrets bool) (model.Finding, bool) {
	if info == nil {
		return model.Finding{}, false
	}
	if info.Mode().Perm()&0o002 == 0 {
		return model.Finding{}, false
	}

	pathLower := strings.ToLower(filepath.ToSlash(absPath))
	isSensitive := false
	switch {
	case strings.HasSuffix(pathLower, "/skill.md"):
		isSensitive = true
	case strings.HasSuffix(pathLower, "/mcp.json"):
		isSensitive = true
	case strings.HasSuffix(pathLower, "/claude_desktop_config.json"):
		isSensitive = true
	case strings.HasSuffix(pathLower, "/.skeptic-state.json"):
		isSensitive = true
	case strings.Contains(pathLower, "/.github/workflows/") && (strings.HasSuffix(pathLower, ".yml") || strings.HasSuffix(pathLower, ".yaml")):
		isSensitive = true
	case strings.HasSuffix(pathLower, ".rulepack.json"), strings.HasSuffix(pathLower, ".rules.json"):
		isSensitive = true
	}
	if !isSensitive {
		return model.Finding{}, false
	}

	return model.Finding{
		RuleID:          "SKN-PROT-001",
		Title:           "World-writable security-critical artifact",
		Description:     "Security-sensitive scanner artifact is world-writable, allowing low-privilege tampering of trusted scanner inputs.",
		Category:        "scanner-hardening",
		Mitre:           "T1222.002",
		Severity:        model.SeverityHigh,
		File:            fileLabel,
		Match:           security.SanitizeMatch(fileLabel, redactSecrets),
		ConfidenceClass: model.DefaultConfidenceForRuleID("SKN-PROT-001"),
	}, true
}

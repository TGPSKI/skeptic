package scan

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/TGPSKI/skeptic/internal/checks"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

func startWorkers(
	ctx context.Context,
	workers int,
	jobs <-chan scanTask,
	pathRules, contentRules []model.Rule,
	opts model.ScanOptions,
	acMatcher *ACMatcher,
	acHintRules map[string][]model.Rule,
) <-chan scanResult {
	results := make(chan scanResult, workers*8)
	var workersWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			for task := range jobs {
				select {
				case <-ctx.Done():
					results <- scanResult{path: task.path, err: ctx.Err()}
					continue
				default:
				}
				t0 := time.Now()
				res := scanFile(task.path, task.root, pathRules, contentRules, scanFileOpts{
					MaxBytes:               opts.MaxBytes,
					UseAbsolutePath:        task.useAbsolutePath,
					IgnorePermissionErrors: opts.IgnorePermissionErrors,
					RedactSecrets:          opts.RedactSecrets,
					MaxFindingsPerFile:     opts.MaxFindingsPerFile,
					ScanStyle:              opts.ScanStyle,
					ThreatMode:             opts.ThreatMode,
					PolicyChecks:           opts.PolicyChecks,
					ACMatcher:              acMatcher,
					ACHintRules:            acHintRules,
					NFKC:                   opts.NFKC,
					MaxDecodeDepth:         opts.MaxDecodeDepth,
					XORBrute:               opts.XORBrute,
				})
				results <- scanResult{
					path:             task.path,
					findings:         res.findings,
					scanned:          res.scanned,
					skipped:          res.skipped,
					permissionErrors: res.permissionErrors,
					duration:         time.Since(t0),
					err:              res.err,
				}
			}
		}()
	}
	go func() {
		workersWG.Wait()
		close(results)
	}()
	return results
}

// ScanSingleFile scans one file with the given rules and options.
func ScanSingleFile(path, root string, pathRules, contentRules []model.Rule, opts ScanFileOptions) ScanFileResult {
	r := scanFile(path, root, pathRules, contentRules, opts)
	return ScanFileResult{
		Findings:         r.findings,
		Scanned:          r.scanned,
		Skipped:          r.skipped,
		PermissionErrors: r.permissionErrors,
		Err:              r.err,
	}
}

//nolint:gocyclo // per-file scan with decoder/check/threshold branches
func scanFile(
	path string,
	root string,
	pathRules []model.Rule,
	contentRules []model.Rule,
	opts scanFileOpts,
) scanFileResult {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsPermission(err) && opts.IgnorePermissionErrors {
			return scanFileResult{skipped: 1, permissionErrors: 1}
		}
		return scanFileResult{err: err}
	}
	if !info.Mode().IsRegular() {
		return scanFileResult{}
	}
	if info.Size() > opts.MaxBytes {
		return scanFileResult{skipped: 1}
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsPermission(err) && opts.IgnorePermissionErrors {
			return scanFileResult{skipped: 1, permissionErrors: 1}
		}
		return scanFileResult{err: err}
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			fmt.Fprintf(os.Stderr, "warning: close %s: %v\n", path, cerr)
		}
	}()

	fileLabel := toRelativeSlash(root, path)
	if opts.UseAbsolutePath {
		fileLabel = filepath.ToSlash(path)
	}
	lowerPath := strings.ToLower(fileLabel)
	lowerAbsPath := strings.ToLower(filepath.ToSlash(path))
	findings := make([]model.Finding, 0)
	seenLocal := make(map[string]struct{}, 16)

	if len(lowerAbsPath) > ebpfPathVisibilityLimit {
		addFinding(&findings, seenLocal, model.Finding{
			RuleID:          "ATK-DEF-EBPF-001",
			Title:           "Potential eBPF path truncation evasion path length",
			Description:     "Path length exceeds common eBPF stack visibility bounds and may reduce runtime sensor context fidelity.",
			Category:        "defense-evasion",
			Mitre:           "T1027",
			Severity:        model.SeverityMedium,
			File:            fileLabel,
			Match:           fmt.Sprintf("path-length=%d", len(lowerAbsPath)),
			ConfidenceClass: model.DefaultConfidenceForRuleID("ATK-DEF-EBPF-001"),
		})
	}
	if finding, ok := worldWritableArtifactFinding(path, fileLabel, info, opts.RedactSecrets); ok {
		addFinding(&findings, seenLocal, finding)
	}

	for _, rule := range pathRules {
		if len(findings) >= opts.MaxFindingsPerFile {
			break
		}
		if rule.RE.MatchString(lowerPath) || (!opts.UseAbsolutePath && rule.RE.MatchString(lowerAbsPath)) {
			addFinding(&findings, seenLocal, model.Finding{
				RuleID:          rule.ID,
				Title:           rule.Title,
				Description:     rule.Description,
				Category:        rule.Category,
				Mitre:           rule.Mitre,
				Severity:        rule.Severity,
				File:            fileLabel,
				Match:           security.SanitizeMatch(fileLabel, opts.RedactSecrets),
				Remediation:     rule.Remediation,
				Confidence:      1.0,
				ConfidenceClass: resolveConfidenceClass(rule),
			})
		}
	}

	prefix := make([]byte, 8192)
	n, readErr := file.Read(prefix)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		if os.IsPermission(readErr) && opts.IgnorePermissionErrors {
			return scanFileResult{findings: findings, skipped: 1, permissionErrors: 1}
		}
		return scanFileResult{err: readErr}
	}
	isText := LooksLikeText(prefix[:n])
	if sigs := DetectPolyglot(prefix[:n]); len(sigs) > 0 {
		emitPolyglot := true
		if !isText {
			formats := make(map[string]struct{})
			for _, sig := range sigs {
				formats[sig.Format] = struct{}{}
			}
			if len(formats) < 3 {
				emitPolyglot = false
			}
		}
		if emitPolyglot {
			for _, sig := range sigs {
				addFinding(&findings, seenLocal, model.Finding{
					RuleID:          "ENC-POLYGLOT-001",
					Title:           "Polyglot file signature detected",
					Description:     fmt.Sprintf("File contains a %s binary signature at offset %d, which may indicate a polyglot file used to evade content-type checks.", sig.Format, sig.Offset),
					Category:        "obfuscation",
					Mitre:           "T1027.001",
					Severity:        model.SeverityHigh,
					File:            fileLabel,
					Match:           fmt.Sprintf("format=%s offset=%d", sig.Format, sig.Offset),
					ConfidenceClass: model.ConfidenceDefinitive,
				})
			}
		}
	}
	if !isText {
		return scanFileResult{findings: findings, scanned: 1}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return scanFileResult{err: err}
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	lines := make([]string, 0, 256)
	var fullContentBuilder strings.Builder
	linesCapped := false

	for scanner.Scan() {
		line := scanner.Text()
		if len(lines) < maxScanLines {
			lines = append(lines, line)
		} else if !linesCapped {
			linesCapped = true
		}
		if fullContentBuilder.Len() < int(opts.MaxBytes) {
			fullContentBuilder.WriteString(line)
			fullContentBuilder.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		if os.IsPermission(err) && opts.IgnorePermissionErrors {
			return scanFileResult{findings: findings, scanned: 1, skipped: 1, permissionErrors: 1}
		}
		return scanFileResult{err: err}
	}
	content := fullContentBuilder.String()
	lowerContent := strings.ToLower(content)
	if opts.NFKC {
		lowerContent = NormalizeNFKC(lowerContent)
	}

	if linesCapped {
		lines = nil
	}

	eligibleRules := prefilterContentRules(contentRules, lowerContent, lowerPath, lowerAbsPath, opts)

	if model.ScanStyleUsesPattern(opts.ScanStyle) {
		scanContentLines(lines, eligibleRules, fileLabel, opts, &findings, seenLocal)
	}
	if model.ScanStyleUsesPattern(opts.ScanStyle) && len(findings) < opts.MaxFindingsPerFile {
		scanDecodedPayloads(content, eligibleRules, fileLabel, opts, &findings, seenLocal)
	}
	runPostPatternChecks(path, fileLabel, lines, content, opts, &findings, seenLocal)

	return scanFileResult{findings: findings, scanned: 1}
}

func prefilterContentRules(
	contentRules []model.Rule,
	lowerContent, lowerPath, lowerAbsPath string,
	opts scanFileOpts,
) []model.Rule {
	if !model.ScanStyleUsesPattern(opts.ScanStyle) {
		return nil
	}
	if opts.ACMatcher != nil && opts.ACHintRules != nil {
		matchedHints := opts.ACMatcher.Match([]byte(lowerContent))
		hintSet := make(map[string]struct{}, len(matchedHints))
		for _, h := range matchedHints {
			hintSet[h] = struct{}{}
		}
		eligible := make([]model.Rule, 0, len(contentRules))
		for _, rule := range contentRules {
			if rule.PathPattern != nil && !rule.PathPattern.MatchString(lowerPath) && !rule.PathPattern.MatchString(lowerAbsPath) {
				continue
			}
			if rule.LiteralHint == "" {
				eligible = append(eligible, rule)
			} else if _, ok := hintSet[rule.LiteralHint]; ok {
				eligible = append(eligible, rule)
			}
		}
		return eligible
	}
	eligible := make([]model.Rule, 0, len(contentRules))
	for _, rule := range contentRules {
		if rule.PathPattern != nil && !rule.PathPattern.MatchString(lowerPath) && !rule.PathPattern.MatchString(lowerAbsPath) {
			continue
		}
		if rule.LiteralHint == "" || strings.Contains(lowerContent, rule.LiteralHint) {
			eligible = append(eligible, rule)
		}
	}
	return eligible
}

func scanContentLines(
	lines []string,
	eligibleRules []model.Rule,
	fileLabel string,
	opts scanFileOpts,
	findings *[]model.Finding,
	seen map[string]struct{},
) {
	for lineIdx, line := range lines {
		if len(*findings) >= opts.MaxFindingsPerFile {
			break
		}
		if len(line) > maxRegexLineLen {
			continue
		}
		matchLine := line
		if opts.NFKC {
			matchLine = NormalizeNFKC(strings.ToLower(line))
		}
		for _, rule := range eligibleRules {
			if rule.RE.MatchString(matchLine) {
				if rule.ContextPattern != nil && !hasContextMatch(lines, lineIdx, rule.ContextPattern, rule.ContextWindow) {
					continue
				}
				if rule.ExcludePattern != nil && rule.ExcludePattern.MatchString(matchLine) {
					continue
				}
				conf := 1.0
				if IsHighEntropy([]byte(line), DefaultEntropyThresholdBits) {
					conf = 1.1
				}
				addFinding(findings, seen, model.Finding{
					RuleID:          rule.ID,
					Title:           rule.Title,
					Description:     rule.Description,
					Category:        rule.Category,
					Mitre:           rule.Mitre,
					Severity:        rule.Severity,
					File:            fileLabel,
					Line:            lineIdx + 1,
					Match:           security.SanitizeMatch(model.CompactSnippet(line), opts.RedactSecrets),
					Remediation:     rule.Remediation,
					Confidence:      conf,
					ConfidenceClass: resolveConfidenceClass(rule),
				})
				if len(*findings) >= opts.MaxFindingsPerFile {
					break
				}
			}
		}
	}
}

func scanDecodedPayloads(
	content string,
	eligibleRules []model.Rule,
	fileLabel string,
	opts scanFileOpts,
	findings *[]model.Finding,
	seen map[string]struct{},
) {
	maxDepth := opts.MaxDecodeDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}
	raw := []byte(content)
	layers := DecodePayloadLayersWithDepth(raw, maxDepth)
	for _, layer := range layers {
		if len(*findings) >= opts.MaxFindingsPerFile {
			break
		}
		decoded := string(layer.Content)
		lowerDecoded := strings.ToLower(decoded)
		matchDecoded := decoded
		if opts.NFKC {
			lowerDecoded = NormalizeNFKC(lowerDecoded)
			matchDecoded = NormalizeNFKC(strings.ToLower(decoded))
		}
		for _, rule := range eligibleRules {
			if len(*findings) >= opts.MaxFindingsPerFile {
				break
			}
			if rule.LiteralHint != "" && !strings.Contains(lowerDecoded, rule.LiteralHint) {
				continue
			}
			if rule.RE.MatchString(matchDecoded) {
				conf := layer.Confidence
				if IsHighEntropy([]byte(decoded), DefaultEntropyThresholdBits) {
					conf += 0.1
				}
				addFinding(findings, seen, model.Finding{
					RuleID:          rule.ID,
					Title:           rule.Title,
					Description:     rule.Description,
					Category:        rule.Category,
					Mitre:           rule.Mitre,
					Severity:        rule.Severity,
					File:            fileLabel,
					Match:           security.SanitizeMatch(model.CompactSnippet(decoded), opts.RedactSecrets),
					Remediation:     rule.Remediation,
					EncodingChain:   layer.Encoding,
					Confidence:      conf,
					ConfidenceClass: resolveConfidenceClass(rule),
				})
			}
		}
	}

	if opts.XORBrute && len(*findings) < opts.MaxFindingsPerFile && ShannonEntropy(raw) > 6.5 {
		hintMatch := func(decoded []byte) bool {
			if opts.ACMatcher != nil {
				return opts.ACMatcher.MatchAny(decoded)
			}
			return true
		}
		if xorOut, ok := TryDecodeXORBrute(raw, hintMatch); ok {
			decoded := string(xorOut)
			lowerDecoded := strings.ToLower(decoded)
			matchDecoded := decoded
			if opts.NFKC {
				lowerDecoded = NormalizeNFKC(lowerDecoded)
				matchDecoded = NormalizeNFKC(strings.ToLower(decoded))
			}
			layer := DecodedLayer{
				Encoding:   "xor-brute",
				Content:    xorOut,
				Confidence: confidenceForDecodeDepth(maxDepth),
			}
			for _, rule := range eligibleRules {
				if len(*findings) >= opts.MaxFindingsPerFile {
					break
				}
				if rule.LiteralHint != "" && !strings.Contains(lowerDecoded, rule.LiteralHint) {
					continue
				}
				if rule.RE.MatchString(matchDecoded) {
					conf := layer.Confidence
					if IsHighEntropy(xorOut, DefaultEntropyThresholdBits) {
						conf += 0.1
					}
					addFinding(findings, seen, model.Finding{
						RuleID:          rule.ID,
						Title:           rule.Title,
						Description:     rule.Description,
						Category:        rule.Category,
						Mitre:           rule.Mitre,
						Severity:        rule.Severity,
						File:            fileLabel,
						Match:           security.SanitizeMatch(model.CompactSnippet(decoded), opts.RedactSecrets),
						Remediation:     rule.Remediation,
						EncodingChain:   layer.Encoding,
						Confidence:      conf,
						ConfidenceClass: resolveConfidenceClass(rule),
					})
				}
			}
		}
	}
}

func runPostPatternChecks(
	path, fileLabel string,
	lines []string,
	content string,
	opts scanFileOpts,
	findings *[]model.Finding,
	seen map[string]struct{},
) {
	if opts.PolicyChecks && len(*findings) < opts.MaxFindingsPerFile {
		for _, finding := range checks.RunPolicyChecks(path, fileLabel, lines, content, opts.RedactSecrets) {
			addFinding(findings, seen, finding)
			if len(*findings) >= opts.MaxFindingsPerFile {
				break
			}
		}
	}
	if model.ScanStyleUsesBehavior(opts.ScanStyle) && len(*findings) < opts.MaxFindingsPerFile {
		for _, finding := range checks.RunBehaviorChainChecks(fileLabel, content, opts.RedactSecrets) {
			addFinding(findings, seen, finding)
			if len(*findings) >= opts.MaxFindingsPerFile {
				break
			}
		}
	}
	if len(*findings) < opts.MaxFindingsPerFile {
		for _, finding := range checks.RunFocusChecks(path, fileLabel, lines, content, opts.RedactSecrets, opts.ThreatMode) {
			addFinding(findings, seen, finding)
			if len(*findings) >= opts.MaxFindingsPerFile {
				break
			}
		}
	}
	if len(*findings) < opts.MaxFindingsPerFile {
		for _, finding := range checks.CheckDomainTyposquat(fileLabel, content, opts.RedactSecrets) {
			addFinding(findings, seen, finding)
			if len(*findings) >= opts.MaxFindingsPerFile {
				break
			}
		}
	}
	if len(*findings) < opts.MaxFindingsPerFile && len(content) > 512 {
		anomalies := DetectEntropyAnomalies([]byte(content), 256, 64, 2.0)
		if len(anomalies) > 3 {
			addFinding(findings, seen, model.Finding{
				RuleID:      "ENC-ENTROPY-001",
				Title:       "Multiple high-entropy regions detected",
				Description: fmt.Sprintf("File contains %d anomalous high-entropy regions (window=256, threshold=2.0 bits above file average), suggesting embedded encoded or encrypted payloads.", len(anomalies)),
				Category:    "obfuscation",
				Mitre:       "T1027",
				Severity:    model.SeverityMedium,
				File:        fileLabel,
				Match:       fmt.Sprintf("anomaly_count=%d file_avg_entropy=%.2f", len(anomalies), ShannonEntropy([]byte(content))),
			})
		}
	}
}

func hasContextMatch(lines []string, matchIdx int, ctxRE *regexp.Regexp, window int) bool {
	start := matchIdx - window
	if start < 0 {
		start = 0
	}
	end := matchIdx + window
	if end >= len(lines) {
		end = len(lines) - 1
	}
	for i := start; i <= end; i++ {
		if i == matchIdx {
			continue
		}
		if ctxRE.MatchString(lines[i]) {
			return true
		}
	}
	return false
}

func addFinding(list *[]model.Finding, seen map[string]struct{}, finding model.Finding) {
	key := fmt.Sprintf("%s|%s|%d|%s", finding.RuleID, finding.File, finding.Line, finding.Match)
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*list = append(*list, finding)
}

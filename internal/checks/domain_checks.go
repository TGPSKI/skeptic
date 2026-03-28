package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// KnownVendorDomains maps canonical vendor/infrastructure domains used in the
// security and software supply chain ecosystems. Near-misses to these domains
// in scanned content indicate typosquat C2 infrastructure or phishing.
var KnownVendorDomains = []string{
	"aquasecurity.com",
	"github.com",
	"github.io",
	"gitlab.com",
	"bitbucket.org",
	"npmjs.org",
	"npmjs.com",
	"pypi.org",
	"rubygems.org",
	"crates.io",
	"pkg.go.dev",
	"docker.com",
	"docker.io",
	"kubernetes.io",
	"amazon.com",
	"amazonaws.com",
	"microsoft.com",
	"azure.com",
	"google.com",
	"googleapis.com",
	"cloudflare.com",
	"fastly.com",
	"hashicorp.com",
	"terraform.io",
	"snyk.io",
	"sonatype.com",
	"jfrog.com",
	"circleci.com",
	"travisci.com",
	"jenkins.io",
	"sentry.io",
	"datadog.com",
	"grafana.com",
	"elastic.co",
	"atlassian.com",
	"vercel.com",
	"netlify.com",
	"herokuapp.com",
	"readthedocs.io",
}

var domainExtractRE = regexp.MustCompile(
	`(?i)(?:https?://|[a-z0-9._%+\-]+@)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)`,
)

// VendorOwnedAltDomains maps known vendor-owned alternate TLDs to their
// canonical domain. These are first-party zones the vendor provably controls
// (e.g. github.io is GitHub Pages, atlassian.net is Jira Cloud) and should
// not fire as TLD swap typosquats.
var VendorOwnedAltDomains = map[string]string{
	"github.io":      "github.com",
	"atlassian.net":  "atlassian.com",
	"google.dev":     "google.com",
	"terraform.io":   "hashicorp.com",
	"kubernetes.io":  "kubernetes.io",
	"readthedocs.io": "readthedocs.io",
	"docker.io":      "docker.com",
	"crates.io":      "crates.io",
	"sentry.io":      "sentry.io",
	"snyk.io":        "snyk.io",
	"jenkins.io":     "jenkins.io",
	"elastic.co":     "elastic.co",
}

// Common TLD swaps used in domain impersonation.
var tldSwaps = map[string][]string{
	"com": {"org", "net", "io", "co", "dev"},
	"org": {"com", "net", "io", "co"},
	"net": {"com", "org", "io"},
	"io":  {"com", "org", "co", "dev"},
	"co":  {"com", "io"},
	"dev": {"com", "io"},
}

// Visual confusables for ASCII domain names. Maps characters that look similar
// when rendered in common fonts.
// Single-character visual confusables for domain names.
var domainHomoglyphs = map[byte]byte{
	'0': 'o',
	'1': 'l',
}

// Multi-character homoglyphs (rn→m, vv→w) applied during normalization.
var multiCharHomoglyphs = map[string]string{
	"rn": "m",
	"vv": "w",
}

// CheckDomainTyposquat extracts domains from file content and compares them
// against KnownVendorDomains for near-miss impersonation. It emits:
//   - DOM-TYPO-001: edit distance near-miss (1-2 edits, ratio ≤ 0.2)
//   - DOM-TYPO-002: TLD swap (body matches exactly, TLD is a common swap)
//   - DOM-TYPO-003: homoglyph substitution (visually confusable characters)
//
// CheckDomainTyposquat extracts domains from file content and compares them
// against KnownVendorDomains for near-miss impersonation. For each domain found,
// it strips subdomains to align segment count with the vendor domain before
// comparing, so scan.aquasecurtiy.com is compared against aquasecurity.com.
func CheckDomainTyposquat(fileLabel, content string, redactSecrets bool) []model.Finding {
	var findings []model.Finding
	seen := make(map[string]struct{})

	matches := domainExtractRE.FindAllStringSubmatch(content, 200)
	for _, m := range matches {
		fullDomain := strings.ToLower(m[1])
		if _, dup := seen[fullDomain]; dup {
			continue
		}
		seen[fullDomain] = struct{}{}

		if isKnownDomain(fullDomain) {
			continue
		}

		for _, vendor := range KnownVendorDomains {
			baseDomain := alignDomainSegments(fullDomain, vendor)
			if baseDomain == vendor {
				continue
			}

			if f, ok := checkTLDSwap(baseDomain, vendor, fileLabel, redactSecrets); ok {
				findings = append(findings, f)
				break
			}
			if f, ok := checkHomoglyph(baseDomain, vendor, fileLabel, redactSecrets); ok {
				findings = append(findings, f)
				break
			}
			if f, ok := checkEditDistance(baseDomain, vendor, fileLabel, redactSecrets); ok {
				findings = append(findings, f)
				break
			}
		}
	}
	return findings
}

// alignDomainSegments extracts the rightmost N segments from domain to match
// the segment count of vendor. e.g., vendor="aquasecurity.com" (2 segments)
// strips "scan.aquasecurtiy.com" to "aquasecurtiy.com".
func alignDomainSegments(domain, vendor string) string {
	vendorParts := strings.Split(vendor, ".")
	domainParts := strings.Split(domain, ".")
	if len(domainParts) <= len(vendorParts) {
		return domain
	}
	return strings.Join(domainParts[len(domainParts)-len(vendorParts):], ".")
}

func isKnownDomain(domain string) bool {
	for _, v := range KnownVendorDomains {
		if domain == v {
			return true
		}
		if strings.HasSuffix(domain, "."+v) {
			return true
		}
	}
	return false
}

func domainBody(domain string) (string, string) {
	idx := strings.LastIndex(domain, ".")
	if idx <= 0 {
		return domain, ""
	}
	return domain[:idx], domain[idx+1:]
}

func checkTLDSwap(domain, vendor, fileLabel string, redact bool) (model.Finding, bool) {
	dBody, dTLD := domainBody(domain)
	vBody, vTLD := domainBody(vendor)

	if dBody != vBody || dTLD == vTLD {
		return model.Finding{}, false
	}

	if _, known := VendorOwnedAltDomains[dBody+"."+dTLD]; known {
		return model.Finding{}, false
	}

	swaps, ok := tldSwaps[vTLD]
	if !ok {
		return model.Finding{}, false
	}
	for _, swap := range swaps {
		if dTLD == swap {
			return model.Finding{
				RuleID:          "DOM-TYPO-002",
				ConfidenceClass: model.ConfidenceDefinitive,
				Title:           "Vendor domain TLD swap",
				Description:     fmt.Sprintf("Domain %q has the same body as %q but with a swapped TLD (.%s → .%s). This is a common domain impersonation technique used to host malicious payloads that appear legitimate.", domain, vendor, vTLD, dTLD),
				Category:        "supply-chain",
				Mitre:           "T1583.001",
				Severity:        model.SeverityHigh,
				File:            fileLabel,
				Match:           security.SanitizeMatch(domain, redact),
				Remediation:     "Verify the domain resolves to the legitimate vendor. Replace with the canonical domain if this is impersonation.",
			}, true
		}
	}
	return model.Finding{}, false
}

func checkHomoglyph(domain, vendor, fileLabel string, redact bool) (model.Finding, bool) {
	if domain == vendor {
		return model.Finding{}, false
	}

	normalized := normalizeHomoglyphs(domain)
	if normalized == vendor && domain != vendor {
		return model.Finding{
			RuleID:          "DOM-TYPO-003",
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           "Vendor domain homoglyph impersonation",
			Description:     fmt.Sprintf("Domain %q contains visually confusable characters that normalize to %q. This is a sophisticated impersonation technique where the domain looks correct at a glance but resolves to attacker infrastructure.", domain, vendor),
			Category:        "supply-chain",
			Mitre:           "T1583.001",
			Severity:        model.SeverityCritical,
			File:            fileLabel,
			Match:           security.SanitizeMatch(domain, redact),
			Remediation:     "This is almost certainly malicious. Replace with the canonical domain and investigate the source of the reference.",
		}, true
	}
	return model.Finding{}, false
}

func normalizeHomoglyphs(s string) string {
	result := s
	for old, replacement := range multiCharHomoglyphs {
		result = strings.ReplaceAll(result, old, replacement)
	}
	var b strings.Builder
	b.Grow(len(result))
	for i := 0; i < len(result); i++ {
		ch := result[i]
		if replacement, ok := domainHomoglyphs[ch]; ok {
			b.WriteByte(replacement)
		} else {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func checkEditDistance(domain, vendor, fileLabel string, redact bool) (model.Finding, bool) {
	dist := EditDistance(domain, vendor)
	if dist == 0 || dist > 2 {
		return model.Finding{}, false
	}

	maxLen := len(domain)
	if len(vendor) > maxLen {
		maxLen = len(vendor)
	}
	if maxLen == 0 {
		return model.Finding{}, false
	}
	ratio := float64(dist) / float64(maxLen)
	if ratio > 0.2 {
		return model.Finding{}, false
	}

	return model.Finding{
		RuleID:          "DOM-TYPO-001",
		ConfidenceClass: model.ConfidenceHeuristic,
		Title:           "Vendor domain near-miss typosquat",
		Description:     fmt.Sprintf("Domain %q is %d edit(s) from known vendor domain %q (ratio %.2f). Near-miss domains are used to host malicious payloads that evade visual review.", domain, dist, vendor, ratio),
		Category:        "supply-chain",
		Mitre:           "T1583.001",
		Severity:        model.SeverityCritical,
		File:            fileLabel,
		Match:           security.SanitizeMatch(domain, redact),
		Remediation:     "Verify whether this domain is the legitimate vendor. If it is a typo, correct it. If it appeared in upstream code, treat the source as potentially compromised.",
	}, true
}

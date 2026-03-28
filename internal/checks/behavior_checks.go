package checks

import (
	"regexp"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// BehaviorChainSpec defines an ordered set of regex steps that must all be present.
type BehaviorChainSpec struct {
	ID                 string
	Title              string
	Description        string
	Category           string
	Mitre              string
	Severity           model.Severity
	Steps              []*regexp.Regexp
	Ordered            bool           // when true, step matches must appear in monotonic line-number order
	ExcludePathPattern *regexp.Regexp // skip this chain for files matching this path pattern
}

// BehaviorChainSpecs is the set of multi-step behavior chain heuristics.
var BehaviorChainSpecs = []BehaviorChainSpec{
	{
		ID:          "BHV-SC-001",
		Title:       "Supply chain tamper to first-run exfil behavior chain",
		Description: "Detected chained behavior across mutable install source, credential-access primitive, and outbound network transmission.",
		Category:    "behavior-chain",
		Mitre:       "T1195.002",
		Severity:    model.SeverityCritical,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)\b(curl|wget)\b.{0,200}(raw\.githubusercontent|install\.sh|\|\s*(bash|sh|zsh))|\bpip(?:3)?\s+install\b`),
			regexp.MustCompile(`(?is)\b(printenv|getenv|os\.environ|process\.env)\b|/proc/\d+/mem`),
			regexp.MustCompile(`(?is)\b(curl|wget|invoke-webrequest|requests\.post|http\.post)\b.{0,200}https?://`),
		},
	},
	{
		ID:          "BHV-CI-001",
		Title:       "CI environment enumeration followed by outbound transfer",
		Description: "Detected sequence where environment variables are enumerated and then transmitted externally.",
		Category:    "behavior-chain",
		Mitre:       "T1552.001",
		Severity:    model.SeverityHigh,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)\b(printenv|env)\b`),
			regexp.MustCompile(`(?is)\b(ACTIONS_RUNTIME_TOKEN|GITHUB_TOKEN|AWS_[A-Z_]+|AZURE_[A-Z_]+|GOOGLE_[A-Z_]+)\b`),
			regexp.MustCompile(`(?is)\b(curl|wget|invoke-restmethod|invoke-webrequest)\b.{0,220}https?://`),
		},
	},
	{
		ID:          "BHV-MEM-001",
		Title:       "Process memory harvest to exfil behavior chain",
		Description: "Detected memory access primitive followed by sensitive data targeting and outbound transfer behavior.",
		Category:    "behavior-chain",
		Mitre:       "T1003.007",
		Severity:    model.SeverityCritical,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)(/proc/\d+/mem|process_vm_readv|gcore\s+\d+|ptrace\s*\()`),
			regexp.MustCompile(`(?is)\b(secret|credential|token|password|client_secret|access_token)\b`),
			regexp.MustCompile(`(?is)\b(curl|wget|nc\s|requests\.post|http\.post)\b.{0,220}(https?://|\d{1,3}(?:\.\d{1,3}){3})`),
		},
	},
	{
		ID:          "BHV-K8S-001",
		Title:       "Kubernetes secret harvest and privilege mutation chain",
		Description: "Detected sequence of broad secret enumeration with role binding or control-plane mutation actions.",
		Category:    "behavior-chain",
		Mitre:       "T1530",
		Severity:    model.SeverityHigh,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)kubectl\s+get\s+secrets?\s+(-A|--all-namespaces)`),
			regexp.MustCompile(`(?is)(clusterrolebinding|rolebinding|cluster-admin)`),
			regexp.MustCompile(`(?is)kubectl\s+(apply|patch|create|replace)`),
		},
	},
	{
		ID:          "BHV-API-001",
		Title:       "Potential API object-level authorization probing chain",
		Description: "Detected repeated object identifier and bearer-token access patterns often seen in BOLA/BFLA abuse attempts.",
		Category:    "behavior-chain",
		Mitre:       "T1190",
		Severity:    model.SeverityMedium,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)\b(authorization:\s*bearer|bearer\s+[a-z0-9._-]{10,})`),
			regexp.MustCompile(`(?is)\b(user_id|account_id|tenant_id|customer_id|organization_id)\b`),
			regexp.MustCompile(`(?is)\b(GET|POST|PUT|PATCH|DELETE)\s+/api/`),
		},
	},
	{
		ID:          "BHV-AGENT-001",
		Title:       "Agentic skill install + tool invoke + file write chain",
		Description: "Detected chained patterns for skill registration, tool invocation, and filesystem write in one artifact.",
		Category:    "behavior-chain",
		Mitre:       "T1059",
		Severity:    model.SeverityHigh,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)(install|register).*skill`),
			regexp.MustCompile(`(?is)tool\.(call|invoke|execute)`),
			regexp.MustCompile(`(?is)(writeFile|fs\.write|open.*w)`),
		},
	},
	{
		ID:          "BHV-OIDC-001",
		Title:       "OIDC token acquire + audience-less validate + cross-tenant",
		Description: "Detected token acquisition with tenant identifier but no audience binding signals in the same source.",
		Category:    "behavior-chain",
		Mitre:       "T1550",
		Severity:    model.SeverityHigh,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)(getToken|acquireToken|oidc.*token)`),
			regexp.MustCompile(`(?is)\btenant[_-]?id\b|\btenantId\b|\btenant\b.{0,120}\b(?:token|auth|oidc|oauth|federation|issuer)\b|\b(?:token|auth|oidc|oauth|federation|issuer)\b.{0,120}\btenant\b`),
		},
	},
	{
		ID:          "BHV-CONTAINER-001",
		Title:       "Container base image + entrypoint override + sensitive mount",
		Description: "Detected ordered Dockerfile-style layering with entrypoint mutation and sensitive host or volume paths.",
		Category:    "behavior-chain",
		Mitre:       "T1611",
		Severity:    model.SeverityHigh,
		Ordered:     true,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)FROM\s+`),
			regexp.MustCompile(`(?is)ENTRYPOINT`),
			regexp.MustCompile(`(?is)(VOLUME|mount|-v)\s+[^\n]*?/(?:etc\b|root\b|var/run\b)`),
		},
	},
	{
		ID:          "BHV-SUPPLY-001",
		Title:       "Package install + postinstall hook + outbound connection",
		Description: "Detected install tooling combined with post-install script hooks and outbound network transfer tools.",
		Category:    "behavior-chain",
		Mitre:       "T1195.002",
		Severity:    model.SeverityHigh,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)(npm install|pip install|go get)`),
			regexp.MustCompile(`(?is)(postinstall|post_install)`),
			regexp.MustCompile(`(?is)\b(curl|wget|requests\.post|http\.Post|Invoke-WebRequest)\b`),
		},
	},
	{
		ID:          "BHV-CRED-001",
		Title:       "Credential file read + env access + HTTP exfiltration",
		Description: "Detected ordered sequence of credential file access, environment variable reads, and outbound HTTP client usage.",
		Category:    "behavior-chain",
		Mitre:       "T1552.001",
		Severity:    model.SeverityCritical,
		Ordered:     true,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)\b(read|cat|load|open|readFile|readFileSync|fopen)\b.{0,100}(id_rsa|credentials|aws_credentials|client_secret)`),
			regexp.MustCompile(`(?is)(os\.environ|process\.env|getenv)`),
			regexp.MustCompile(`(?is)(http\.Post|requests\.post|fetch.*POST)`),
		},
	},
	{
		ID:          "BHV-ORD-001",
		Title:       "Ordered download, write, chmod, execute chain",
		Description: "Detected curl/wget download followed by write/tee, chmod, then shell execution on later lines.",
		Category:    "behavior-chain",
		Mitre:       "T1059",
		Severity:    model.SeverityHigh,
		Ordered:     true,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)\b(curl|wget)\b`),
			regexp.MustCompile(`(?is)(\btee\b|>>|\bwrite\s)`),
			regexp.MustCompile(`(?is)\bchmod\b`),
			regexp.MustCompile(`(?is)(\b(bash|sh)\b|\bexec\b)`),
		},
	},
	{
		ID:          "BHV-ORD-002",
		Title:       "Ordered credential read then HTTP exfil",
		Description: "Detected reading credential material then outbound HTTP POST/curl on later lines.",
		Category:    "behavior-chain",
		Mitre:       "T1048",
		Severity:    model.SeverityCritical,
		Ordered:     true,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)(\bread\b|\bcat\b|\.pem|\bcredentials\b|\bid_rsa\b)`),
			regexp.MustCompile(`(?is)(\b(curl|wget)\b.*POST|http\.Post|requests\.post)`),
		},
	},
	{
		ID:          "BHV-ORD-003",
		Title:       "Ordered clone, modify, push chain",
		Description: "Detected git clone followed by modification tooling then git push on later lines.",
		Category:    "behavior-chain",
		Mitre:       "T1195.002",
		Severity:    model.SeverityHigh,
		Ordered:     true,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)\bgit\s+clone\b`),
			regexp.MustCompile(`(?is)(\b(sed|awk|perl)\b|modify|patch)`),
			regexp.MustCompile(`(?is)\bgit\s+push\b`),
		},
	},
	{
		ID:          "BHV-ORD-004",
		Title:       "Ordered environment enumeration, encoding, and HTTP POST exfiltration",
		Description: "Detected environment enumeration followed by base64-style encoding then outbound POST or HTTP client usage on later lines.",
		Category:    "behavior-chain",
		Mitre:       "T1041",
		Severity:    model.SeverityCritical,
		Ordered:     true,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)(\benv\b|\bprintenv\b|os\.environ|System\.getenv|\bENV\[|Get-ChildItem\s+Env:)`),
			regexp.MustCompile(`(?is)(\bbase64\b|\bbtoa\b|\bb64encode\b|\[Convert\]::ToBase64String|\bencode64\b)`),
			regexp.MustCompile(`(?is)(\bPOST\b|fetch\(|requests\.post|curl.*-X\s*POST|http\.Post|Invoke-WebRequest)`),
		},
	},
	{
		ID:          "BHV-ORD-005",
		Title:       "Ordered package install, postinstall hook, and reverse shell",
		Description: "Detected package manager install followed by post-install or build hook markers then reverse-shell primitives on later lines.",
		Category:    "behavior-chain",
		Mitre:       "T1195.002",
		Severity:    model.SeverityCritical,
		Ordered:     true,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)(npm\s+install|pip\s+install|gem\s+install|\bgo\s+get\b|cargo\s+install|composer\s+require)`),
			regexp.MustCompile(`(?is)(postinstall|post_install|setup\.py|setup\.cfg|build\.rs|build\.gradle)`),
			regexp.MustCompile(`(?is)(/dev/tcp/|nc\s+-e\b|\bncat\b|socket\.connect|bash\s+-i|python\s+-c.*socket)`),
		},
	},
	{
		ID:          "BHV-DEPBOT-001",
		Title:       "Dependency bot automerge with no release age gate and mutable ranges",
		Description: "Detected a file containing automerge enablement without minimumReleaseAge or stabilityDays, combined with a non-pinning range strategy. This combination allows compromised upstream packages to be automatically merged within minutes of publication.",
		Category:    "behavior-chain",
		Mitre:       "T1195.002",
		Severity:    model.SeverityCritical,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)"automerge"\s*:\s*true`),
			regexp.MustCompile(`(?is)"rangeStrategy"\s*:\s*"(bump|replace|widen)"`),
		},
	},
	{
		ID:          "BHV-ORD-006",
		Title:       "Ordered image build, secret copy into context, and registry push",
		Description: "Detected container build context followed by copying credential-like paths then registry push tooling on later lines.",
		Category:    "behavior-chain",
		Mitre:       "T1552.001",
		Severity:    model.SeverityHigh,
		Ordered:     true,
		Steps: []*regexp.Regexp{
			regexp.MustCompile(`(?is)(\bdocker\s+build\b|FROM\s+|Dockerfile)`),
			regexp.MustCompile(`(?is)(COPY.*secret|COPY.*key|COPY.*\.env|COPY.*credentials|ADD.*secret|ADD.*\.env)`),
			regexp.MustCompile(`(?is)(\bdocker\s+push\b|crane\s+push|skopeo\s+copy|buildah\s+push)`),
		},
	},
}

// RunBehaviorChainChecks evaluates multi-step attack-chain heuristics against full file content.
func RunBehaviorChainChecks(fileLabel string, content string, redactSecrets bool) []model.Finding {
	findings := make([]model.Finding, 0, len(BehaviorChainSpecs))
	for _, spec := range BehaviorChainSpecs {
		if spec.ExcludePathPattern != nil && spec.ExcludePathPattern.MatchString(fileLabel) {
			continue
		}
		var matchedAll bool
		if spec.Ordered {
			matchedAll = matchOrderedChain(content, spec.Steps)
		} else {
			matchedAll = true
			for _, step := range spec.Steps {
				if !step.MatchString(content) {
					matchedAll = false
					break
				}
			}
		}
		if spec.ID == "BHV-OIDC-001" && HasOIDCAudienceBinding(content) {
			matchedAll = false
		}
		if !matchedAll {
			continue
		}
		line := 0
		match := ""
		if len(spec.Steps) > 0 {
			line = FirstMatchLine(content, spec.Steps[0])
			match = FirstMatchText(content, spec.Steps[0])
		}
		findings = append(findings, model.Finding{
			RuleID:          spec.ID,
			ConfidenceClass: model.ConfidenceHeuristic,
			Title:           spec.Title,
			Description:     spec.Description,
			Category:        spec.Category,
			Mitre:           spec.Mitre,
			Severity:        spec.Severity,
			File:            fileLabel,
			Line:            line,
			Match:           security.SanitizeMatch(strings.TrimSpace(match), redactSecrets),
		})
	}
	return findings
}

func matchOrderedChain(content string, steps []*regexp.Regexp) bool {
	lines := strings.Split(content, "\n")
	prevLine := 0
	for _, step := range steps {
		line := firstMatchLineAfterSplit(lines, step, prevLine)
		if line == 0 {
			return false
		}
		prevLine = line
	}
	return true
}

// firstMatchLineAfterSplit returns the 1-based line number of the first match strictly after minLine,
// or 0 if none. Accepts pre-split lines to avoid re-splitting per step.
func firstMatchLineAfterSplit(lines []string, re *regexp.Regexp, minLine int) int {
	for i := minLine; i < len(lines); i++ {
		if re.MatchString(lines[i]) {
			return i + 1
		}
	}
	if minLine >= len(lines) {
		return 0
	}
	suffix := strings.Join(lines[minLine:], "\n")
	loc := re.FindStringIndex(suffix)
	if loc == nil {
		return 0
	}
	prefix := suffix[:loc[0]]
	return minLine + 1 + strings.Count(prefix, "\n")
}

// FirstMatchLine reports the earliest matching line number for stable finding locations.
func FirstMatchLine(content string, re *regexp.Regexp) int {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if re.MatchString(line) {
			return i + 1
		}
	}
	return 0
}

// FirstMatchText returns a representative snippet for chain findings.
func FirstMatchText(content string, re *regexp.Regexp) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if re.MatchString(line) {
			return line
		}
	}
	// Fallback for multiline only matches.
	if match := re.FindString(content); strings.TrimSpace(match) != "" {
		return match
	}
	return ""
}

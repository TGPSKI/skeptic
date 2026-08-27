package checks

import (
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestRunPolicyChecksWorkflowTrustAndPermissions(t *testing.T) {
	content := `
name: ci
permissions: write-all
jobs:
  build:
    permissions:
      id-token: write
      contents: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:latest
`
	lines := strings.Split(strings.TrimSpace(content), "\n")
	findings := RunPolicyChecks(
		"/repo/.github/workflows/ci.yml",
		".github/workflows/ci.yml",
		lines,
		content,
		true,
	)
	want := map[string]struct{}{
		"POL-GHA-002": {},
		"POL-GHA-003": {},
		"POL-GHA-004": {},
	}
	for _, finding := range findings {
		delete(want, finding.RuleID)
	}
	if len(want) != 0 {
		t.Fatalf("missing expected workflow policy findings: %#v", want)
	}
}

func TestRunPolicyChecksPrivilegedPRCombination(t *testing.T) {
	unsafe := `on:
  pull_request_target:
permissions:
  contents: write
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}`
	findings := RunPolicyChecks("/repo/.github/workflows/pr.yml", ".github/workflows/pr.yml", strings.Split(unsafe, "\n"), unsafe, true)
	assertHasFinding(t, findings, "CI-PRT-001")
	assertHasFinding(t, findings, "CI-PRT-002")

	safe := `on:
  pull_request_target:
permissions:
  pull-requests: write
jobs:
  label:
    steps:
      - uses: actions/checkout@v4`
	findings = RunPolicyChecks("/repo/.github/workflows/label.yml", ".github/workflows/label.yml", strings.Split(safe, "\n"), safe, true)
	assertNoRulePrefix(t, findings, "CI-PRT-")

	unprivileged := `on: pull_request
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}`
	findings = RunPolicyChecks("/repo/.github/workflows/test.yml", ".github/workflows/test.yml", strings.Split(unprivileged, "\n"), unprivileged, true)
	assertNoRulePrefix(t, findings, "CI-PRT-")
}

func TestRunPolicyChecksIgnoresArtifactSubjectPathGlob(t *testing.T) {
	content := `permissions:
  id-token: write
steps:
  - uses: actions/attest-build-provenance@v2
    with:
      subject-path: 'dist/*.tar.gz'`
	findings := RunPolicyChecks("/repo/.github/workflows/release.yml", ".github/workflows/release.yml", strings.Split(content, "\n"), content, true)
	assertNoRulePrefix(t, findings, "POL-CLOUDID-001")
}

func TestRunPolicyChecksDependencyIntegrity(t *testing.T) {
	reqContent := "requests==2.31.0\nurllib3==2.2.1\n"
	reqFindings := RunPolicyChecks(
		"/repo/requirements.txt",
		"requirements.txt",
		strings.Split(strings.TrimSpace(reqContent), "\n"),
		reqContent,
		true,
	)
	assertHasFinding(t, reqFindings, "POL-PIP-001")

	pkgContent := `{"dependencies":{"left-pad":"^1.3.0"}}`
	pkgFindings := RunPolicyChecks(
		"/repo/package.json",
		"package.json",
		[]string{pkgContent},
		pkgContent,
		true,
	)
	assertHasFinding(t, pkgFindings, "POL-NPM-001")

	dockerfile := "FROM golang:1.24\n"
	dockerFindings := RunPolicyChecks(
		"/repo/Dockerfile",
		"Dockerfile",
		[]string{"FROM golang:1.24"},
		dockerfile,
		true,
	)
	assertHasFinding(t, dockerFindings, "POL-CNT-001")
}

func TestRunPolicyChecksCloudIdentityWildcard(t *testing.T) {
	content := `
{
  "Principal": { "Federated": "token.actions.githubusercontent.com" },
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:*"
    }
  }
}
`
	findings := RunPolicyChecks(
		"/repo/policy.json",
		"policy.json",
		strings.Split(strings.TrimSpace(content), "\n"),
		content,
		true,
	)
	assertHasFinding(t, findings, "POL-CLOUDID-001")
}

func assertHasFinding(t *testing.T, findings []model.Finding, ruleID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return
		}
	}
	t.Fatalf("expected finding %s not present", ruleID)
}

func assertNoRulePrefix(t *testing.T, findings []model.Finding, prefix string) {
	t.Helper()
	for _, finding := range findings {
		if strings.HasPrefix(finding.RuleID, prefix) {
			t.Fatalf("unexpected finding %s", finding.RuleID)
		}
	}
}

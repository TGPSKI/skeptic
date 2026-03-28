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
		"POL-GHA-001": {},
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

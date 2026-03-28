package main

import (
	"context"
	"io"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/mcp"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/rules"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
)

func proofCorpusRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine caller file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "proof")
}

func scanProofFixture(t *testing.T, fixtureName string, mode model.ScanMode) model.Report {
	t.Helper()
	root := filepath.Join(proofCorpusRoot(t), fixtureName)
	report, err := scanpkg.ScanWithOptions(context.Background(), rules.DefaultRules(), model.ScanOptions{
		Paths:                  []string{root},
		Profile:                model.ProfileRepo,
		ScanStyle:              model.ScanStyleHybrid,
		ThreatMode:             model.ThreatModeAll,
		Mode:                   mode,
		PolicyChecks:           true,
		MaxBytes:               scanpkg.DefaultMaxBytes,
		FailOn:                 model.SeverityNone,
		IgnorePermissionErrors: true,
		Workers:                2,
		MaxFindings:            500,
		MaxFindingsPerFile:     100,
		RedactSecrets:          true,
		Logger:                 logging.NewLogger(logging.LogError, io.Discard),
	})
	if err != nil {
		t.Fatalf("scan %s failed: %v", fixtureName, err)
	}
	return report
}

func findingHasRulePrefix(findings []model.Finding, prefix string) bool {
	for _, f := range findings {
		if len(f.RuleID) >= len(prefix) && f.RuleID[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

func findingHasRuleID(findings []model.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func logFindings(t *testing.T, findings []model.Finding) {
	t.Helper()
	for _, f := range findings {
		t.Logf("finding: %s %s (%s) in %s", f.RuleID, f.Title, f.ConfidenceClass, f.File)
	}
}

func TestProofCorpusCleanRepo(t *testing.T) {
	report := scanProofFixture(t, "clean-repo", model.ScanModeDeveloper)
	if len(report.Findings) > 0 {
		for _, f := range report.Findings {
			t.Logf("unexpected finding: %s %s (%s) in %s", f.RuleID, f.Title, f.ConfidenceClass, f.File)
		}
		t.Fatalf("clean-repo should have 0 findings in developer mode, got %d", len(report.Findings))
	}
	ta := mcp.BuildTrustAssessment(report)
	if ta["verdict"] != "no_issues_found" {
		t.Fatalf("clean-repo verdict should be no_issues_found, got %v", ta["verdict"])
	}
}

func TestProofCorpusAgenticPoisoning(t *testing.T) {
	report := scanProofFixture(t, "agentic-poisoning", model.ScanModeDeveloper)
	if len(report.Findings) == 0 {
		t.Fatal("agentic-poisoning should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "AGT-TRUST-") {
		t.Error("expected at least one AGT-TRUST- finding")
	}
	for _, f := range report.Findings {
		if f.ConfidenceClass == "" {
			t.Errorf("finding %s has empty confidence class", f.RuleID)
		}
	}
	ta := mcp.BuildTrustAssessment(report)
	verdict := ta["verdict"].(string)
	if verdict == "no_issues_found" {
		t.Error("agentic-poisoning verdict should not be no_issues_found")
	}
	hasLockfile := findingHasRuleID(report.Findings, "AGT-TRUST-013") || findingHasRuleID(report.Findings, "AGT-TRUST-014")
	if !hasLockfile {
		t.Error("expected AGT-TRUST-013 or AGT-TRUST-014 (lockfile injection)")
	}
	if !findingHasRuleID(report.Findings, "AGT-TRUST-015") {
		t.Error("expected AGT-TRUST-015 (IDE config injection)")
	}
	if !findingHasRuleID(report.Findings, "AGT-TRUST-017") {
		t.Error("expected AGT-TRUST-017 (backup file injection)")
	}
}

func TestProofCorpusCITrustAbuse(t *testing.T) {
	report := scanProofFixture(t, "ci-trust-abuse", model.ScanModeDeveloper)
	if len(report.Findings) == 0 {
		t.Fatal("ci-trust-abuse should have findings")
	}
	hasCIMutable := findingHasRulePrefix(report.Findings, "SCM-TRUST-") || findingHasRulePrefix(report.Findings, "CI-MUTABLE-")
	hasCIPRT := findingHasRulePrefix(report.Findings, "CI-PRT-")
	if !hasCIMutable && !hasCIPRT {
		t.Error("expected SCM-TRUST-/CI-MUTABLE- or CI-PRT- finding")
	}
}

func TestProofCorpusDomainImpersonation(t *testing.T) {
	report := scanProofFixture(t, "domain-impersonation", model.ScanModeDeveloper)
	if !findingHasRulePrefix(report.Findings, "DOM-TYPO-") {
		for _, f := range report.Findings {
			t.Logf("finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one DOM-TYPO- finding")
	}
}

func TestProofCorpusCampaignArtifacts(t *testing.T) {
	devReport := scanProofFixture(t, "campaign-artifacts", model.ScanModeDeveloper)
	irReport := scanProofFixture(t, "campaign-artifacts", model.ScanModeIR)
	if !findingHasRuleID(irReport.Findings, "ATK-C2-006") {
		t.Error("ir mode should surface trycloudflare tunnel finding (ATK-C2-006)")
	}
	if len(irReport.Findings) < len(devReport.Findings) {
		t.Errorf("ir mode (%d findings) should have >= developer mode (%d findings)", len(irReport.Findings), len(devReport.Findings))
	}
}

func TestProofCorpusPersistence(t *testing.T) {
	// ATK-PER-* rules are heuristic at medium/high severity; IR mode needed to surface them.
	report := scanProofFixture(t, "persistence", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("persistence should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "ATK-PER-") {
		for _, f := range report.Findings {
			t.Logf("finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one ATK-PER- finding")
	}
}

func TestProofCorpusEncodedPayloads(t *testing.T) {
	// ENC-EXFIL-* and OBF-CMD-* are heuristic at high/medium severity; IR mode needed.
	report := scanProofFixture(t, "encoded-payloads", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("encoded-payloads should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "ENC-EXFIL-") {
		for _, f := range report.Findings {
			t.Logf("finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one ENC-EXFIL- finding")
	}
	if !findingHasRulePrefix(report.Findings, "OBF-CMD-") {
		t.Error("expected at least one OBF-CMD- finding")
	}
}

func TestProofCorpusContainerEscape(t *testing.T) {
	report := scanProofFixture(t, "container-escape", model.ScanModeDeveloper)
	if len(report.Findings) == 0 {
		t.Fatal("container-escape should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "CTR-ESC-") {
		for _, f := range report.Findings {
			t.Logf("finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one CTR-ESC- finding")
	}
}

func TestProofCorpusCIPolicyAbuse(t *testing.T) {
	devReport := scanProofFixture(t, "ci-policy-abuse", model.ScanModeDeveloper)
	if len(devReport.Findings) == 0 {
		t.Fatal("ci-policy-abuse should have findings in developer mode")
	}
	if !findingHasRulePrefix(devReport.Findings, "POL-") {
		for _, f := range devReport.Findings {
			t.Logf("finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one POL- finding")
	}
	// CI-ABUSE-* rules are heuristic at high/medium severity; IR mode needed.
	irReport := scanProofFixture(t, "ci-policy-abuse", model.ScanModeIR)
	if !findingHasRulePrefix(irReport.Findings, "CI-ABUSE-") {
		for _, f := range irReport.Findings {
			t.Logf("ir finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one CI-ABUSE- finding in ir mode")
	}
}

func TestProofCorpusMachineIdentity(t *testing.T) {
	report := scanProofFixture(t, "machine-identity", model.ScanModeDeveloper)
	if len(report.Findings) == 0 {
		t.Fatal("machine-identity should have findings")
	}
	hasCloudID := findingHasRulePrefix(report.Findings, "CLOUD-ID-")
	hasMID := findingHasRulePrefix(report.Findings, "MID-")
	hasIAC := findingHasRulePrefix(report.Findings, "IAC-")
	if !hasCloudID && !hasMID && !hasIAC {
		for _, f := range report.Findings {
			t.Logf("finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one CLOUD-ID-, MID-, or IAC- finding")
	}
}

func TestProofCorpusAgenticMCPAbuse(t *testing.T) {
	// AGT-MEM-* includes critical findings that surface in developer mode.
	devReport := scanProofFixture(t, "agentic-mcp-abuse", model.ScanModeDeveloper)
	if len(devReport.Findings) == 0 {
		t.Fatal("agentic-mcp-abuse should have findings")
	}
	if !findingHasRulePrefix(devReport.Findings, "AGT-MEM-") {
		t.Error("expected at least one AGT-MEM- finding in developer mode")
	}
	// AGT-MCP-* rules are heuristic at high/medium severity; IR mode needed.
	irReport := scanProofFixture(t, "agentic-mcp-abuse", model.ScanModeIR)
	if !findingHasRulePrefix(irReport.Findings, "AGT-MCP-") {
		for _, f := range irReport.Findings {
			t.Logf("ir finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one AGT-MCP- finding in ir mode")
	}
}

func TestProofCorpusRugPullIndicators(t *testing.T) {
	// RUGPULL-* rules are heuristic at medium/low severity; IR mode needed.
	report := scanProofFixture(t, "rug-pull-indicators", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("rug-pull-indicators should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "RUGPULL-") {
		for _, f := range report.Findings {
			t.Logf("finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one RUGPULL- finding")
	}
}

func TestProofCorpusSupplyChainHygiene(t *testing.T) {
	report := scanProofFixture(t, "supply-chain-hygiene", model.ScanModeDeveloper)
	if len(report.Findings) == 0 {
		t.Fatal("supply-chain-hygiene should have findings")
	}
	hasSCMGit := findingHasRulePrefix(report.Findings, "SCM-GIT-")
	hasSCMPkg := findingHasRulePrefix(report.Findings, "SCM-PKG-")
	hasSCMCache := findingHasRulePrefix(report.Findings, "SCM-CACHE-")
	hasSCMTemp := findingHasRulePrefix(report.Findings, "SCM-TEMP-")
	hasSCMSym := findingHasRulePrefix(report.Findings, "SCM-SYM-")
	if !hasSCMGit && !hasSCMPkg && !hasSCMCache && !hasSCMTemp && !hasSCMSym {
		logFindings(t, report.Findings)
		t.Error("expected at least one SCM-GIT-, SCM-PKG-, SCM-CACHE-, SCM-TEMP-, or SCM-SYM- finding")
	}
	if !hasSCMSym {
		t.Error("expected at least one SCM-SYM- finding from symlink fixtures")
	}
}

func TestProofCorpusAIWorkload(t *testing.T) {
	// AIW-* focus checks are heuristic at medium/high; IR mode needed.
	report := scanProofFixture(t, "ai-workload", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("ai-workload should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "AIW-") {
		for _, f := range report.Findings {
			t.Logf("finding: %s %s in %s", f.RuleID, f.Title, f.File)
		}
		t.Error("expected at least one AIW- finding")
	}
}

func TestProofCorpusC2AndExfil(t *testing.T) {
	// ATK-C2-* and ATK-DEF-* are heuristic at low severity; IR mode needed.
	report := scanProofFixture(t, "c2-and-exfil", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("c2-and-exfil should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "ATK-C2-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one ATK-C2- finding")
	}
	if !findingHasRulePrefix(report.Findings, "ATK-DEF-") {
		t.Error("expected at least one ATK-DEF- finding")
	}
}

// --- Strength Lane 1: Agentic Ecosystem ---

func TestProofCorpusAgenticSkills(t *testing.T) {
	report := scanProofFixture(t, "agentic-skills", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("agentic-skills should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "AGT-SKL-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one AGT-SKL- finding")
	}
}

func TestProofCorpusAgenticOutputInjection(t *testing.T) {
	report := scanProofFixture(t, "agentic-output-injection", model.ScanModeDeveloper)
	if len(report.Findings) == 0 {
		t.Fatal("agentic-output-injection should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "AGT-OUT-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one AGT-OUT- finding")
	}
}

// --- Strength Lane 2: CI/CD Trust Boundaries ---

func TestProofCorpusCISecretHygiene(t *testing.T) {
	report := scanProofFixture(t, "ci-secret-hygiene", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("ci-secret-hygiene should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "CI-SECRET-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one CI-SECRET- finding")
	}
}

// --- Strength Lane 3: Low-Review Surfaces (the moat) ---

func TestProofCorpusLowReviewSurfaces(t *testing.T) {
	report := scanProofFixture(t, "low-review-surfaces", model.ScanModeDeveloper)
	if len(report.Findings) == 0 {
		t.Fatal("low-review-surfaces should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "AGT-TRUST-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one AGT-TRUST- finding (lockfile/IDE/backup/CODEOWNERS injection)")
	}
	if !findingHasRulePrefix(report.Findings, "SCM-GIT-") {
		t.Error("expected at least one SCM-GIT- finding (.gitattributes smudge/clean filter)")
	}
	ta := mcp.BuildTrustAssessment(report)
	verdict := ta["verdict"].(string)
	if verdict == "no_issues_found" {
		t.Error("low-review-surfaces verdict should not be no_issues_found")
	}
}

// --- Strength Lane 4: Correlation ---

func TestProofCorpusCorrelation(t *testing.T) {
	report := scanProofFixture(t, "correlation-multi", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("correlation-multi should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "COR-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one COR- correlation finding")
	}
}

// --- Remaining families ---

func TestProofCorpusDropperTechniques(t *testing.T) {
	report := scanProofFixture(t, "dropper-techniques", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("dropper-techniques should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "DROP-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one DROP- finding")
	}
}

func TestProofCorpusNPMCampaignIOCs(t *testing.T) {
	report := scanProofFixture(t, "npm-campaign-iocs", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("npm-campaign-iocs should have findings")
	}
	hasCRED := findingHasRulePrefix(report.Findings, "ATK-SWEEP-") || findingHasRulePrefix(report.Findings, "ATK-EXFIL-")
	if !hasCRED {
		logFindings(t, report.Findings)
		t.Error("expected at least one ATK-SWEEP- or ATK-EXFIL- finding from credential sweep patterns")
	}
}

func TestProofCorpusBehaviorChains(t *testing.T) {
	report := scanProofFixture(t, "behavior-chains", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("behavior-chains should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "BHV-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one BHV- finding")
	}
}

func TestProofCorpusIdentityGraph(t *testing.T) {
	report := scanProofFixture(t, "identity-graph", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("identity-graph should have findings")
	}
	// GRAPH- findings require RunIdentityGraphChecks (enrichment pipeline), which
	// scanProofFixture does not call. Pattern-match rules (MID-, CLOUD-ID-) still fire.
	hasMID := findingHasRulePrefix(report.Findings, "MID-")
	hasCloudID := findingHasRulePrefix(report.Findings, "CLOUD-ID-")
	hasGRAPH := findingHasRulePrefix(report.Findings, "GRAPH-")
	if !hasMID && !hasCloudID && !hasGRAPH {
		logFindings(t, report.Findings)
		t.Error("expected at least one MID-, CLOUD-ID-, or GRAPH- finding")
	}
}

func TestProofCorpusHelmIdentity(t *testing.T) {
	report := scanProofFixture(t, "helm-identity", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("helm-identity should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "IAC-HELM-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one IAC-HELM- finding")
	}
}

func TestProofCorpusAttackExecution(t *testing.T) {
	report := scanProofFixture(t, "attack-execution", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("attack-execution should have findings")
	}
	hasEXE := findingHasRulePrefix(report.Findings, "ATK-EXE-")
	hasLAT := findingHasRulePrefix(report.Findings, "ATK-LAT-")
	hasCOL := findingHasRulePrefix(report.Findings, "ATK-COL-")
	if !hasEXE && !hasLAT && !hasCOL {
		logFindings(t, report.Findings)
		t.Error("expected at least one ATK-EXE-, ATK-LAT-, or ATK-COL- finding")
	}
}

func TestProofCorpusObfuscationEntropy(t *testing.T) {
	report := scanProofFixture(t, "obfuscation-entropy", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("obfuscation-entropy should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "OBF-ENT-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one OBF-ENT- finding")
	}
}

// --- CI/Depbot/Build/Env/Infra rules ---

func TestProofCorpusCIDepbotConfig(t *testing.T) {
	report := scanProofFixture(t, "ci-depbot-config", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("ci-depbot-config should have findings")
	}
	if !findingHasRuleID(report.Findings, "CI-DEPBOT-001") {
		logFindings(t, report.Findings)
		t.Error("expected CI-DEPBOT-001 (no minimumReleaseAge)")
	}
	if !findingHasRuleID(report.Findings, "CI-DEPBOT-003") {
		t.Error("expected CI-DEPBOT-003 (automerge enabled)")
	}
	if !findingHasRuleID(report.Findings, "CI-DEPBOT-004") {
		t.Error("expected CI-DEPBOT-004 (range strategy bump)")
	}
	if !findingHasRulePrefix(report.Findings, "CI-DEPBOT-") {
		t.Error("expected at least one CI-DEPBOT- finding")
	}
}

func TestProofCorpusCIBuildHygiene(t *testing.T) {
	report := scanProofFixture(t, "ci-build-hygiene", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("ci-build-hygiene should have findings")
	}
	if !findingHasRuleID(report.Findings, "CI-BUILD-001") {
		logFindings(t, report.Findings)
		t.Error("expected CI-BUILD-001 (docker login -p)")
	}
	if !findingHasRuleID(report.Findings, "CI-BUILD-003") {
		t.Error("expected CI-BUILD-003 (curl|bash in Dockerfile)")
	}
	if !findingHasRuleID(report.Findings, "CI-BUILD-008") {
		t.Error("expected CI-BUILD-008 (COPY . . or ADD . .)")
	}
	hasBuildPrefix := findingHasRulePrefix(report.Findings, "CI-BUILD-")
	hasEvalPrefix := findingHasRulePrefix(report.Findings, "BHV-EVAL-")
	if !hasBuildPrefix {
		t.Error("expected at least one CI-BUILD- finding")
	}
	if !hasEvalPrefix {
		t.Error("expected at least one BHV-EVAL- finding from dynamic.sh")
	}
}

func TestProofCorpusCIEnvExposure(t *testing.T) {
	report := scanProofFixture(t, "ci-env-exposure", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("ci-env-exposure should have findings")
	}
	if !findingHasRulePrefix(report.Findings, "CI-ENV-") {
		logFindings(t, report.Findings)
		t.Error("expected at least one CI-ENV- finding")
	}
	if !findingHasRuleID(report.Findings, "CI-ENV-004") {
		t.Error("expected CI-ENV-004 (source <(curl))")
	}
}

func TestProofCorpusInfraPolicy(t *testing.T) {
	report := scanProofFixture(t, "infra-policy", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("infra-policy should have findings")
	}
	if !findingHasRuleID(report.Findings, "POL-TF-001") {
		logFindings(t, report.Findings)
		t.Error("expected POL-TF-001 (S3 backend without encrypt)")
	}
	if !findingHasRuleID(report.Findings, "CI-ENV-007") {
		t.Error("expected CI-ENV-007 (committed terraform.tfvars)")
	}
	if !findingHasRuleID(report.Findings, "DEP-TOOL-001") {
		t.Error("expected DEP-TOOL-001 (go install @latest)")
	}
	if !findingHasRulePrefix(report.Findings, "CI-ENV-006") {
		t.Error("expected CI-ENV-006 (Helm values password default)")
	}
}

func TestProofCorpusAgenticMCPCreds(t *testing.T) {
	report := scanProofFixture(t, "agentic-mcp-creds", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("agentic-mcp-creds should have findings")
	}
	if !findingHasRuleID(report.Findings, "AGT-MCP-019") {
		logFindings(t, report.Findings)
		t.Error("expected AGT-MCP-019 (MCP env credential interpolation)")
	}
	if !findingHasRuleID(report.Findings, "AGT-MCP-020") {
		t.Error("expected AGT-MCP-020 (broad git permissions)")
	}
	if !findingHasRuleID(report.Findings, "AGT-SKL-017") {
		t.Error("expected AGT-SKL-017 (wildcard cluster CLI)")
	}
}

func TestProofCorpusDepbotCIAttackChain(t *testing.T) {
	report := scanProofFixture(t, "depbot-ci-attack-chain", model.ScanModeIR)
	if len(report.Findings) == 0 {
		t.Fatal("depbot-ci-attack-chain should have findings")
	}
	if !findingHasRuleID(report.Findings, "CI-DEPBOT-001") {
		logFindings(t, report.Findings)
		t.Error("expected CI-DEPBOT-001 (no minimumReleaseAge)")
	}
	if !findingHasRuleID(report.Findings, "SCM-PKG-003") {
		t.Error("expected SCM-PKG-003 (install hooks in package.json)")
	}
	if !findingHasRuleID(report.Findings, "COR-006") {
		logFindings(t, report.Findings)
		t.Error("expected COR-006 (depbot + install hooks correlation)")
	}
}

// --- Negative tests ---

func TestProofCorpusNegativeBenign(t *testing.T) {
	report := scanProofFixture(t, "negative-benign", model.ScanModeDeveloper)
	for _, f := range report.Findings {
		if findingHasRulePrefix([]model.Finding{f}, "AGT-TRUST-") || findingHasRulePrefix([]model.Finding{f}, "SCM-GIT-") {
			t.Errorf("unexpected finding in benign fixture: %s %s in %s", f.RuleID, f.Title, f.File)
		}
	}
}

func trustAssessmentNumericOK(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return true
	default:
		return false
	}
}

func TestTrustAssessmentShape(t *testing.T) {
	report := scanProofFixture(t, "agentic-poisoning", model.ScanModeDeveloper)
	if len(report.Findings) == 0 {
		t.Fatal("agentic-poisoning should have at least one finding")
	}
	ta := mcp.BuildTrustAssessment(report)

	if _, ok := ta["verdict"].(string); !ok {
		t.Fatalf("verdict: want string, got %T", ta["verdict"])
	}
	for _, key := range []string{"definitive_count", "heuristic_count", "correlated_count"} {
		if !trustAssessmentNumericOK(ta[key]) {
			t.Fatalf("%s: want numeric, got %T", key, ta[key])
		}
	}
	if !trustAssessmentNumericOK(ta["risk_score"]) {
		t.Fatalf("risk_score: want numeric, got %T", ta["risk_score"])
	}

	riskAreas, ok := ta["risk_areas"].([]map[string]any)
	if !ok {
		t.Fatalf("risk_areas: want []map[string]any, got %T", ta["risk_areas"])
	}
	for i, area := range riskAreas {
		for _, k := range []string{"category", "count", "max_severity", "confidence"} {
			if _, exists := area[k]; !exists {
				t.Fatalf("risk_areas[%d]: missing key %q", i, k)
			}
		}
		if !trustAssessmentNumericOK(area["count"]) {
			t.Fatalf("risk_areas[%d].count: want numeric, got %T", i, area["count"])
		}
	}

	reviewPri, ok := ta["review_priority"].([]map[string]any)
	if !ok {
		t.Fatalf("review_priority: want []map[string]any, got %T", ta["review_priority"])
	}
	for i, entry := range reviewPri {
		for _, k := range []string{"file", "score", "reasons"} {
			if _, exists := entry[k]; !exists {
				t.Fatalf("review_priority[%d]: missing key %q", i, k)
			}
		}
		if _, ok := entry["file"].(string); !ok {
			t.Fatalf("review_priority[%d].file: want string, got %T", i, entry["file"])
		}
		if !trustAssessmentNumericOK(entry["score"]) {
			t.Fatalf("review_priority[%d].score: want numeric, got %T", i, entry["score"])
		}
		switch reasons := entry["reasons"].(type) {
		case []string:
		case []any:
			for j, r := range reasons {
				if _, ok := r.(string); !ok {
					t.Fatalf("review_priority[%d].reasons[%d]: want string element, got %T", i, j, r)
				}
			}
		default:
			t.Fatalf("review_priority[%d].reasons: want []string or []any, got %T", i, entry["reasons"])
		}
	}
}

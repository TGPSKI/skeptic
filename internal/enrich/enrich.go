package enrich

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/TGPSKI/skeptic/internal/checks"
	"github.com/TGPSKI/skeptic/internal/correlation"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/mcp"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/provenance"
)

// Options controls which post-scan enrichment steps run.
type Options struct {
	PolicyChecks      bool
	IdentityGraphHops int
	RedactSecrets     bool

	ProvenanceManifestPath          string
	RequireSignedProvenanceManifest bool
	SBOMPath                        string

	AutoDiscoverMCP bool

	BehaviorBaselinePath    string
	DriftSeverityMultiplier float64
	DriftAllowedChainsRaw   string
	BehaviorHistoryPath     string

	GitCorrelation bool
}

// EnrichReport runs all post-scan enrichment steps on the report in-place.
// Steps include dependency checks, identity graph analysis, provenance
// verification, SBOM cross-referencing, MCP discovery, behavior drift
// detection, and git-history correlation.
// A nil logger is accepted and treated as a no-op (discard) logger.
func EnrichReport(report *model.Report, opts Options, roots []string, threatMode model.ThreatMode, logger *logging.Logger) {
	if logger == nil {
		logger = logging.NewLogger(logging.LogError, nil)
	}
	if opts.PolicyChecks {
		report.Findings = append(report.Findings, checks.RunDepChecks(roots, opts.RedactSecrets)...)
	}
	if threatMode == model.ThreatModeAll || threatMode == model.ThreatModeMachineIdentity {
		report.Findings = append(report.Findings, checks.RunIdentityGraphChecks(roots, opts.IdentityGraphHops, opts.RedactSecrets)...)
	}
	if opts.ProvenanceManifestPath != "" {
		report.Findings = append(report.Findings, provenance.RunProvenanceChecks(roots, opts.ProvenanceManifestPath, opts.RequireSignedProvenanceManifest, opts.RedactSecrets)...)
	}
	enrichSBOM(report, opts, roots, logger)
	if opts.AutoDiscoverMCP {
		configs := mcp.DiscoverMCPClients()
		if len(configs) > 0 {
			logger.Infof("MCP auto-discovery found %d client configs", len(configs))
			report.Findings = append(report.Findings, mcp.RunMCPDiscoveryChecks(configs, opts.RedactSecrets)...)
		}
	}
	enrichBehaviorBaseline(report, opts, logger)
	enrichBehaviorHistory(report, opts, logger)
	if opts.GitCorrelation {
		repoRoot := "."
		if len(roots) > 0 {
			repoRoot = roots[0]
		}
		if absRoot, err := filepath.Abs(repoRoot); err == nil {
			repoRoot = absRoot
		}
		report.Findings = append(report.Findings, correlation.CorrelateByGitHistory(report.Findings, repoRoot)...)
	}
}

func enrichSBOM(report *model.Report, opts Options, roots []string, logger *logging.Logger) {
	if strings.TrimSpace(opts.SBOMPath) == "" {
		return
	}
	sbomData, sbomErr := os.ReadFile(opts.SBOMPath)
	if sbomErr != nil {
		logger.Warnf("failed to read SBOM: %v", sbomErr)
		return
	}
	components, parseErr := provenance.ParseCycloneDXBOM(sbomData)
	if parseErr != nil || len(components) == 0 {
		components, parseErr = provenance.ParseSPDXBOM(sbomData)
	}
	if parseErr != nil {
		logger.Warnf("failed to parse SBOM: %v", parseErr)
		return
	}
	if len(components) == 0 {
		return
	}
	manifests := checks.DiscoverManifests(roots)
	allHashes := make(map[string]string)
	for _, mf := range manifests {
		data, readErr := os.ReadFile(mf.Path)
		if readErr != nil {
			continue
		}
		for k, v := range provenance.ExtractPackageHashes(mf.Ecosystem, data) {
			allHashes[k] = v
		}
	}
	report.Findings = append(report.Findings, provenance.CrossReferenceSBOM(components, allHashes, opts.SBOMPath, opts.RedactSecrets)...)
}

func enrichBehaviorBaseline(report *model.Report, opts Options, logger *logging.Logger) {
	if opts.BehaviorBaselinePath == "" {
		return
	}
	currentProfile := correlation.BuildBehaviorProfile(report.Findings, report.ScannedFiles)
	previousProfile, loadErr := correlation.LoadBehaviorProfile(opts.BehaviorBaselinePath)
	if loadErr == nil {
		driftCfg := correlation.DriftConfig{
			SeverityShiftMultiplier: opts.DriftSeverityMultiplier,
			ProfileVersion:          correlation.BehaviorProfileVersion,
		}
		if driftCfg.SeverityShiftMultiplier <= 0 {
			driftCfg.SeverityShiftMultiplier = correlation.DefaultDriftConfig().SeverityShiftMultiplier
		}
		if opts.DriftAllowedChainsRaw != "" {
			for _, part := range strings.Split(opts.DriftAllowedChainsRaw, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					driftCfg.AllowedNewChains = append(driftCfg.AllowedNewChains, part)
				}
			}
		}
		dr := correlation.ComputeDrift(currentProfile, previousProfile, driftCfg)
		report.Findings = append(report.Findings, correlation.DriftToFindings(dr)...)
	}
	if saveErr := correlation.SaveBehaviorProfile(opts.BehaviorBaselinePath, currentProfile); saveErr != nil {
		logger.Warnf("failed to save behavior profile: %v", saveErr)
	}
}

func enrichBehaviorHistory(report *model.Report, opts Options, logger *logging.Logger) {
	histPath := strings.TrimSpace(opts.BehaviorHistoryPath)
	if histPath == "" {
		return
	}
	history, histErr := correlation.LoadProfileHistory(histPath)
	if histErr != nil {
		logger.Warnf("failed to load profile history %s: %v (starting fresh)", histPath, histErr)
		history = correlation.ProfileHistory{}
	}
	currentProfile := correlation.BuildBehaviorProfile(report.Findings, report.ScannedFiles)
	history.Push(currentProfile)
	report.Findings = append(report.Findings, history.ComputeTrend()...)
	if saveErr := correlation.SaveProfileHistory(histPath, history); saveErr != nil {
		logger.Warnf("failed to save profile history: %v", saveErr)
	}
}

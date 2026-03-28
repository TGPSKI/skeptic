package report

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// ExportEvidenceOptions configures evidence bundle creation (CLI fills this after flag parsing).
type ExportEvidenceOptions struct {
	ReportPath  string
	OutPath     string
	SignBundle  bool
	PrivKeyPath string
}

// RunExportEvidence bundles scan findings into a signed .tar.gz for incident response handoff.
func RunExportEvidence(stdout io.Writer, stderr io.Writer, opts ExportEvidenceOptions) int {
	reportPath := strings.TrimSpace(opts.ReportPath)
	if reportPath == "" {
		fmt.Fprintln(stderr, "--report is required")
		return 2
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed reading report: %v\n", err)
		return 1
	}
	var rep model.Report
	if err := json.Unmarshal(reportData, &rep); err != nil {
		fmt.Fprintf(stderr, "failed parsing report JSON: %v\n", err)
		return 1
	}
	outPath := strings.TrimSpace(opts.OutPath)
	if outPath == "" {
		outPath = fmt.Sprintf("evidence-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	}

	file, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(stderr, "failed creating output: %v\n", err)
		return 1
	}
	closeFile := true
	defer func() {
		if closeFile {
			if cerr := file.Close(); cerr != nil {
				fmt.Fprintf(stderr, "warning: close evidence file: %v\n", cerr)
			}
		}
	}()
	gw := gzip.NewWriter(file)
	tw := tar.NewWriter(gw)

	reportJSON, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "failed to marshal findings: %v\n", err)
		return 1
	}
	if err := AddTarEntry(tw, "findings.json", reportJSON); err != nil {
		fmt.Fprintf(stderr, "failed writing findings: %v\n", err)
		return 1
	}

	manifest := BuildEvidenceManifest(rep, reportJSON)
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "failed to marshal manifest: %v\n", err)
		return 1
	}
	if err := AddTarEntry(tw, "manifest.json", manifestJSON); err != nil {
		fmt.Fprintf(stderr, "failed writing manifest: %v\n", err)
		return 1
	}

	snippets := BuildEvidenceSnippets(rep)
	snippetsJSON, err := json.MarshalIndent(snippets, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "failed to marshal snippets: %v\n", err)
		return 1
	}
	if err := AddTarEntry(tw, "snippets.json", snippetsJSON); err != nil {
		fmt.Fprintf(stderr, "failed writing snippets: %v\n", err)
		return 1
	}

	if opts.SignBundle && strings.TrimSpace(opts.PrivKeyPath) != "" {
		bundleHash := sha256.Sum256(append(reportJSON, manifestJSON...))
		sig, signErr := SignWithEd25519(opts.PrivKeyPath, bundleHash[:])
		if signErr != nil {
			fmt.Fprintf(stderr, "signing failed: %v\n", signErr)
			return 1
		}
		if err := AddTarEntry(tw, "signature.sig", sig); err != nil {
			fmt.Fprintf(stderr, "failed writing signature: %v\n", err)
			return 1
		}
	}

	if err := tw.Close(); err != nil {
		fmt.Fprintf(stderr, "failed finalizing tar: %v\n", err)
		return 1
	}
	if err := gw.Close(); err != nil {
		fmt.Fprintf(stderr, "failed finalizing gzip: %v\n", err)
		return 1
	}
	closeFile = false
	if err := file.Close(); err != nil {
		fmt.Fprintf(stderr, "failed writing evidence file: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "evidence bundle written: %s\n", outPath)
	return 0
}

// AddTarEntry writes one file entry to a tar archive.
func AddTarEntry(tw *tar.Writer, name string, data []byte) error {
	header := &tar.Header{
		Name:    name,
		Size:    int64(len(data)),
		Mode:    0o644,
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// BuildEvidenceManifest builds manifest metadata for an evidence bundle.
func BuildEvidenceManifest(report model.Report, reportJSON []byte) map[string]any {
	hash := sha256.Sum256(reportJSON)
	return map[string]any{
		"generated_at":     time.Now().UTC().Format(time.RFC3339),
		"report_sha256":    hex.EncodeToString(hash[:]),
		"total_findings":   len(report.Findings),
		"scanned_files":    report.ScannedFiles,
		"ruleset_hash":     report.RulesetHash,
		"scan_style":       report.ScanStyle,
		"threat_mode":      report.ThreatMode,
		"severity_summary": report.FindingsBySeverity,
	}
}

// BuildEvidenceSnippets builds per-finding snippet records for an evidence bundle.
func BuildEvidenceSnippets(report model.Report) []map[string]any {
	snippets := make([]map[string]any, 0, len(report.Findings))
	for _, f := range report.Findings {
		snippets = append(snippets, map[string]any{
			"rule_id":  f.RuleID,
			"severity": f.Severity,
			"file":     f.File,
			"line":     f.Line,
			"match":    f.Match,
		})
	}
	return snippets
}

// SignWithEd25519 signs data using an Ed25519 private key from a PEM file.
func SignWithEd25519(privKeyPath string, data []byte) ([]byte, error) {
	keyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}
	privKey, err := ParseEd25519PrivateKeyPEM(keyData)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(privKey, data), nil
}

// ParseEd25519PrivateKeyPEM delegates to security.ParseEd25519PrivateKeyPEM.
func ParseEd25519PrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	return security.ParseEd25519PrivateKeyPEM(data)
}

// ParseEd25519PublicKeyPEM delegates to security.ParseEd25519PublicKeyPEM.
func ParseEd25519PublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	return security.ParseEd25519PublicKeyPEM(data)
}

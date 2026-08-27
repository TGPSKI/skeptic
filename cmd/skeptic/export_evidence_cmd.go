package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	configpkg "github.com/TGPSKI/skeptic/internal/config"
	reportpkg "github.com/TGPSKI/skeptic/internal/report"
)

func runExportEvidenceGlobal(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	stop, profErr := globalProfileAndStop(gf, stderr)
	if profErr != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", profErr)
		return 1
	}
	defer stop()
	return runExportEvidence(args, stdout, stderr)
}

func runExportEvidence(args []string, stdout io.Writer, stderr io.Writer) int {
	var (
		reportPath  string
		outPath     string
		signBundle  bool
		privKeyPath string
	)
	fs := flag.NewFlagSet("skeptic export-evidence", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintSubcommandHeader(stderr, "export-evidence", "Package a JSON scan report as an evidence bundle.", []string{"skeptic export-evidence --report report.json --out evidence.tar.gz"})
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"o": "out",
		}, nil)
	}
	fs.StringVar(&reportPath, "report", "", "JSON scan report path")
	fs.StringVar(&outPath, "out", "", "output .tar.gz path (default: evidence-<timestamp>.tar.gz)")
	fs.StringVar(&outPath, "o", "", "output .tar.gz path")
	fs.BoolVar(&signBundle, "sign", false, "sign with Ed25519 private key")
	fs.StringVar(&privKeyPath, "private-key", "", "Ed25519 private key PEM for signing")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if strings.TrimSpace(reportPath) == "" {
		fmt.Fprintln(stderr, "--report is required")
		return 2
	}
	return reportpkg.RunExportEvidence(stdout, stderr, reportpkg.ExportEvidenceOptions{
		ReportPath:  reportPath,
		OutPath:     outPath,
		SignBundle:  signBundle,
		PrivKeyPath: privKeyPath,
	})
}

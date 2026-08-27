package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	configpkg "github.com/TGPSKI/skeptic/internal/config"
	"github.com/TGPSKI/skeptic/internal/model"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
	"github.com/TGPSKI/skeptic/internal/suppress"
)

func runWaiveGlobal(args []string, stdout, stderr io.Writer, gf globalFlags) int {
	stop, profErr := globalProfileAndStop(gf, stderr)
	if profErr != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", profErr)
		return 1
	}
	defer stop()
	return runWaive(mergeGlobalFlagsIntoArgs(gf, args, false), stdout, stderr)
}

func runWaive(args []string, stdout, stderr io.Writer) int {
	var (
		repoPath   string
		file       string
		ruleID     string
		reason     string
		outPath    string
		configPath string
	)
	fs := flag.NewFlagSet("skeptic waive", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintSubcommandHeader(stderr, "waive", "Create SHA256-pinned waivers for reviewed findings.", []string{"skeptic waive --path . --file README.md --rule SCM-TRUST-001 --reason 'documentation example'"})
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"p": "path", "r": "rule", "o": "out", "c": "config",
		}, nil)
	}
	fs.StringVar(&repoPath, "path", ".", "repository path to scan")
	fs.StringVar(&repoPath, "p", ".", "repository path to scan")
	fs.StringVar(&file, "file", "", "file to waive (relative path within repo)")
	fs.StringVar(&ruleID, "rule", "", "rule ID to waive")
	fs.StringVar(&ruleID, "r", "", "rule ID to waive")
	fs.StringVar(&reason, "reason", "", "waiver reason (required)")
	fs.StringVar(&outPath, "out", "", "waiver file path (default: .skeptic-waivers.json)")
	fs.StringVar(&outPath, "o", "", "waiver file path")
	fs.StringVar(&configPath, "config", "", "config file path (empty = auto-discover)")
	fs.StringVar(&configPath, "c", "", "config file path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	scanFn := func(path string) (*model.Report, error) {
		scanArgs := []string{"--path", path, "--format", "json", "--fail-on", "none", "--quiet"}
		if configPath != "" {
			scanArgs = append(scanArgs, "--config", configPath)
		}
		report, code := performSkepticRun(
			scanArgs,
			io.Discard, stderr, scanpkg.ScanWithOptions, skepticRunMode{SkipStdout: true},
		)
		if code != 0 && len(report.Findings) == 0 {
			return nil, fmt.Errorf("scan exited with code %d", code)
		}
		return &report, nil
	}

	result, err := suppress.RunWaive(suppress.WaiveOptions{
		RepoPath:   repoPath,
		File:       file,
		RuleID:     ruleID,
		Reason:     reason,
		WaiverPath: outPath,
	}, scanFn)
	if err != nil {
		fmt.Fprintf(stderr, "waive: %v\n", err)
		return 1
	}

	if result.MatchedFindings == 0 {
		fmt.Fprintf(stdout, "scan: %d findings\nno matching findings to waive\n", result.TotalFindings)
		return 0
	}

	fmt.Fprintf(stdout, "scan: %d findings\n", result.TotalFindings)
	if file != "" && result.FileSHA256 != "" {
		fmt.Fprintf(stdout, "waiving: %d findings on %s (sha256: %.12s...)\n", result.MatchedFindings, file, result.FileSHA256)
	} else {
		fmt.Fprintf(stdout, "waiving: %d findings\n", result.MatchedFindings)
	}
	fmt.Fprintf(stdout, "wrote %d waivers to %s\n", result.WaiversCreated, result.WaiverPath)
	fmt.Fprintf(stdout, "validation: %d active, %d suppressed\n", result.ActiveAfter, result.SuppressedAfter)
	return 0
}

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"

	configpkg "github.com/TGPSKI/skeptic/internal/config"
	"github.com/TGPSKI/skeptic/internal/daemon"
	"github.com/TGPSKI/skeptic/internal/logging"
	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/rules"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
)

func executeDaemonScanForServe(scanArgs []string, logger *logging.Logger, scan daemon.ScanFunc) (model.Report, int, string, error) {
	var errBuf bytes.Buffer
	report, code := performSkepticRun(scanArgs, io.Discard, &errBuf, scan, skepticRunMode{
		ExternalLogger: logger,
		SkipStdout:     true,
	})
	stderrText := errBuf.String()
	if code != 0 && code != 3 {
		return report, code, stderrText, fmt.Errorf("scan exited with code %d", code)
	}
	return report, code, stderrText, nil
}

func runServeGlobal(args []string, stdout, stderr io.Writer, gf globalFlags) int {
	stop, profErr := globalProfileAndStop(gf, stderr)
	if profErr != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", profErr)
		return 1
	}
	defer stop()

	sys, _, _ := configpkg.LoadSystemConfig("")
	return daemon.RunServe(context.Background(), args, stdout, stderr, daemon.DaemonDeps{
		Scan: func(ctx context.Context, r []model.Rule, opts model.ScanOptions) (model.Report, error) {
			return scanpkg.ScanWithOptions(ctx, r, opts)
		},
		ExecuteScan: executeDaemonScanForServe,
		RulesLoaded: len(rules.DefaultRules()),
		GlobalFlags: daemon.GlobalFlagOverrides{
			Verbosity: gf.Verbosity,
			Quiet:     gf.Quiet,
			Config:    gf.Config,
			LogFile:   gf.LogFile,
		},
		SystemConfig: daemon.SystemDaemonConfig{
			DaemonBind:     sys.DaemonBind,
			DaemonTokenDir: sys.DaemonTokenDir,
			LogDir:         sys.LogDir,
		},
	})
}

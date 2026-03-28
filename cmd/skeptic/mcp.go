package main

import (
	"context"
	"fmt"
	"io"

	"github.com/TGPSKI/skeptic/internal/ingest"
	skepticmcp "github.com/TGPSKI/skeptic/internal/mcp"
	"github.com/TGPSKI/skeptic/internal/rules"
)

func runMCPGlobal(args []string, stdout, stderr io.Writer, gf globalFlags) int {
	stop, err := globalProfileAndStop(gf, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", err)
		return 1
	}
	defer stop()

	mergedArgs := mergeGlobalFlagsIntoArgs(gf, args, false)
	return skepticmcp.RunMCP(context.Background(), mergedArgs, stdout, stderr, skepticmcp.Options{
		RunScan: func(ctx context.Context, a []string, out io.Writer, errW io.Writer) int {
			return run(a, out, errW)
		},
		RunIngest:    ingest.RunIngest,
		DefaultRules: rules.DefaultRules,
	})
}

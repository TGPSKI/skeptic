package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
)

type profileOptions struct {
	CPUProfile string
	MemProfile string
	Trace      string
	PerfDebug  bool
}

func registerProfileFlags(fs *flag.FlagSet, prof *profileOptions) {
	fs.StringVar(&prof.CPUProfile, "cpu-profile", "", "write CPU profile to file")
	fs.StringVar(&prof.MemProfile, "mem-profile", "", "write heap profile on exit")
	fs.StringVar(&prof.Trace, "trace", "", "write execution trace to file")
	fs.BoolVar(&prof.PerfDebug, "perf-debug", false, "enable all profiling + per-file timing")
}

func applyPerfDebugDefaults(prof *profileOptions) {
	if prof.CPUProfile == "" {
		prof.CPUProfile = "cpu.prof"
	}
	if prof.MemProfile == "" {
		prof.MemProfile = "mem.prof"
	}
	if prof.Trace == "" {
		prof.Trace = "trace.out"
	}
}

func startProfiling(prof profileOptions, stderr io.Writer) (stopFn func(), err error) {
	var closers []func()
	stopFn = func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}

	if prof.Trace != "" {
		f, fErr := os.Create(prof.Trace)
		if fErr != nil {
			return stopFn, fmt.Errorf("create trace file: %w", fErr)
		}
		if tErr := trace.Start(f); tErr != nil {
			if cerr := f.Close(); cerr != nil {
				return stopFn, fmt.Errorf("start trace: %w (close: %v)", tErr, cerr)
			}
			return stopFn, fmt.Errorf("start trace: %w", tErr)
		}
		fmt.Fprintf(stderr, "profiling: trace → %s\n", prof.Trace)
		closers = append(closers, func() {
			trace.Stop()
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(stderr, "warning: close trace file: %v\n", cerr)
			}
		})
	}

	if prof.CPUProfile != "" {
		f, fErr := os.Create(prof.CPUProfile)
		if fErr != nil {
			return stopFn, fmt.Errorf("create cpu profile: %w", fErr)
		}
		if pErr := pprof.StartCPUProfile(f); pErr != nil {
			if cerr := f.Close(); cerr != nil {
				return stopFn, fmt.Errorf("start cpu profile: %w (close: %v)", pErr, cerr)
			}
			return stopFn, fmt.Errorf("start cpu profile: %w", pErr)
		}
		fmt.Fprintf(stderr, "profiling: cpu → %s\n", prof.CPUProfile)
		closers = append(closers, func() {
			pprof.StopCPUProfile()
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(stderr, "warning: close cpu profile: %v\n", cerr)
			}
		})
	}

	if prof.MemProfile != "" {
		fmt.Fprintf(stderr, "profiling: mem → %s (written on exit)\n", prof.MemProfile)
		closers = append(closers, func() {
			f, fErr := os.Create(prof.MemProfile)
			if fErr != nil {
				fmt.Fprintf(stderr, "create mem profile: %v\n", fErr)
				return
			}
			runtime.GC()
			if wErr := pprof.WriteHeapProfile(f); wErr != nil {
				if cerr := f.Close(); cerr != nil {
					fmt.Fprintf(stderr, "write mem profile: %v (close: %v)\n", wErr, cerr)
				} else {
					fmt.Fprintf(stderr, "write mem profile: %v\n", wErr)
				}
				return
			}
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(stderr, "close mem profile: %v\n", cerr)
			}
		})
	}
	return stopFn, nil
}

// globalProfileAndStop sets up profiling from globalFlags, returning a stop func.
// Subcommands that don't register their own profile flags use this.
func globalProfileAndStop(gf globalFlags, stderr io.Writer) (func(), error) {
	prof := profileOptions{
		CPUProfile: gf.CPUProfile,
		MemProfile: gf.MemProfile,
		Trace:      gf.Trace,
		PerfDebug:  gf.PerfDebug,
	}
	if prof.PerfDebug {
		applyPerfDebugDefaults(&prof)
	}
	if prof.CPUProfile == "" && prof.MemProfile == "" && prof.Trace == "" {
		return func() {}, nil
	}
	return startProfiling(prof, stderr)
}

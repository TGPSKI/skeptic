package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"

	configpkg "github.com/TGPSKI/skeptic/internal/config"
	reportpkg "github.com/TGPSKI/skeptic/internal/report"
	"github.com/TGPSKI/skeptic/internal/rules"
)

func runBundleGlobal(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	stop, profErr := globalProfileAndStop(gf, stderr)
	if profErr != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", profErr)
		return 1
	}
	defer stop()
	return runBundle(args, stdout, stderr)
}

func runVerifyBundleGlobal(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	stop, profErr := globalProfileAndStop(gf, stderr)
	if profErr != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", profErr)
		return 1
	}
	defer stop()
	return runVerifyBundle(args, stdout, stderr)
}

func runBundle(args []string, stdout io.Writer, stderr io.Writer) int {
	var (
		platform    string
		signBundle  bool
		privKeyPath string
		outPath     string
	)
	fs := flag.NewFlagSet("skeptic bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, map[string]string{
			"o": "out",
		}, nil)
	}
	fs.StringVar(&platform, "platform", runtime.GOOS+"/"+runtime.GOARCH, "target platform os/arch")
	fs.BoolVar(&signBundle, "sign", false, "sign bundle with Ed25519 key")
	fs.StringVar(&privKeyPath, "private-key", "", "Ed25519 private key PEM for signing")
	fs.StringVar(&outPath, "out", "", "output bundle path")
	fs.StringVar(&outPath, "o", "", "output bundle path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	return reportpkg.RunBundle(stdout, stderr, reportpkg.BundleOptions{
		Platform:    platform,
		OutPath:     outPath,
		SignBundle:  signBundle,
		PrivKeyPath: privKeyPath,
		Rules:       rules.DefaultRules(),
		GoVersion:   buildGoVersion,
		Commit:      buildCommit,
	})
}

func runVerifyBundle(args []string, stdout io.Writer, stderr io.Writer) int {
	var (
		bundlePath string
		pubKeyPath string
	)
	fs := flag.NewFlagSet("skeptic verify-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		configpkg.PrintFormattedFlags(fs, stderr, nil, nil)
	}
	fs.StringVar(&bundlePath, "bundle", "", "path to .tar.gz bundle to verify")
	fs.StringVar(&pubKeyPath, "public-key", "", "Ed25519 public key PEM for verification")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if strings.TrimSpace(bundlePath) == "" || strings.TrimSpace(pubKeyPath) == "" {
		fmt.Fprintln(stderr, "--bundle and --public-key are required")
		return 2
	}
	return reportpkg.RunVerifyBundle(stdout, stderr, reportpkg.VerifyBundleOptions{
		BundlePath: bundlePath,
		PubKeyPath: pubKeyPath,
	})
}

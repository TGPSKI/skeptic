package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/TGPSKI/skeptic/internal/completion"
	configpkg "github.com/TGPSKI/skeptic/internal/config"
	"github.com/TGPSKI/skeptic/internal/ingest"
	"github.com/TGPSKI/skeptic/internal/rules"
	scanpkg "github.com/TGPSKI/skeptic/internal/scan"
)

type runRawOptions = configpkg.RunRawOptions

var (
	buildCommit    = "(dev)"
	buildDate      = "(unknown)"
	buildGoVersion = "(unknown)"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// globalFlags holds flags that are extracted before subcommand dispatch so they
// can be placed anywhere on the command line: `skeptic -v 2 corpus scan`.
type globalFlags struct {
	Verbosity  int
	Quiet      bool
	CPUProfile string
	MemProfile string
	Trace      string
	PerfDebug  bool
	LogFile    string
	Config     string
}

// knownGlobalFlags maps flag names to whether they take a value argument.
var knownGlobalFlags = map[string]bool{
	"--verbose": true, "-v": true,
	"--quiet": false, "-q": false,
	"--cpu-profile": true, "--mem-profile": true, "--trace": true,
	"--perf-debug": false,
	"--log-file":   true, "--config": true, "-c": true,
}

// extractGlobalFlags scans args for global flags, strips them, and returns
// the parsed struct plus the remaining args for subcommand dispatch.
func extractGlobalFlags(args []string) (globalFlags, []string) {
	var gf globalFlags
	var rest []string
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}

		// Handle --flag=value forms
		if eqIdx := strings.IndexByte(a, '='); eqIdx > 0 && strings.HasPrefix(a, "-") {
			name := a[:eqIdx]
			val := a[eqIdx+1:]
			if _, known := knownGlobalFlags[name]; known {
				applyGlobalFlag(&gf, name, val)
				i++
				continue
			}
		}

		if takesVal, known := knownGlobalFlags[a]; known {
			if takesVal {
				if i+1 < len(args) {
					applyGlobalFlag(&gf, a, args[i+1])
					i += 2
					continue
				}
				// Missing value -- leave it for subcommand to error on
				rest = append(rest, a)
				i++
				continue
			}
			applyGlobalFlag(&gf, a, "")
			i++
			continue
		}

		rest = append(rest, a)
		i++
	}
	return gf, rest
}

func applyGlobalFlag(gf *globalFlags, name, val string) {
	switch name {
	case "--verbose", "-v":
		fmt.Sscanf(val, "%d", &gf.Verbosity) //nolint:errcheck // invalid values fall back to 0
	case "--quiet", "-q":
		gf.Quiet = true
	case "--cpu-profile":
		gf.CPUProfile = val
	case "--mem-profile":
		gf.MemProfile = val
	case "--trace":
		gf.Trace = val
	case "--perf-debug":
		gf.PerfDebug = true
	case "--log-file":
		gf.LogFile = val
	case "--config", "-c":
		gf.Config = val
	}
}

func runIngestGlobal(args []string, stdout io.Writer, stderr io.Writer, gf globalFlags) int {
	stop, profErr := globalProfileAndStop(gf, stderr)
	if profErr != nil {
		fmt.Fprintf(stderr, "profiling setup failed: %v\n", profErr)
		return 1
	}
	defer stop()
	merged := mergeGlobalFlagsIntoArgs(gf, args, true)
	return ingest.RunIngest(context.Background(), merged, stdout, stderr)
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	gf, remaining := extractGlobalFlags(args)

	if len(remaining) > 0 {
		switch strings.ToLower(strings.TrimSpace(remaining[0])) {
		case "scan":
			mergedArgs := mergeGlobalFlagsIntoArgs(gf, remaining[1:], true)
			_, code := performSkepticRun(mergedArgs, stdout, stderr, scanpkg.ScanWithOptions, skepticRunMode{})
			return code
		case "ingest":
			return runIngestGlobal(remaining[1:], stdout, stderr, gf)
		case "sign-rulepack":
			return rules.RunSignRulepack(remaining[1:], stdout, stderr)
		case "gen-rule-keypair":
			return rules.RunGenRulepackKeypair(remaining[1:], stdout, stderr)
		case "serve", "daemon":
			return runServeGlobal(remaining[1:], stdout, stderr, gf)
		case "mcp":
			return runMCPGlobal(remaining[1:], stdout, stderr, gf)
		case "init":
			return configpkg.RunInit(remaining[1:], stdout, stderr)
		case "init-config":
			return configpkg.RunInit(remaining[1:], stdout, stderr)
		case "config":
			return configpkg.RunConfig(remaining[1:], stdout, stderr)
		case "version":
			if len(remaining) > 1 && (remaining[1] == "--help" || remaining[1] == "-h") {
				configpkg.PrintSubcommandHeader(stderr, "version", "Print build identity, Go version, and built-in rule count.", []string{"skeptic version"})
				return 0
			}
			return runVersion(stdout)
		case "export-evidence":
			return runExportEvidenceGlobal(remaining[1:], stdout, stderr, gf)
		case "bundle":
			return runBundleGlobal(remaining[1:], stdout, stderr, gf)
		case "verify-bundle":
			return runVerifyBundleGlobal(remaining[1:], stdout, stderr, gf)
		case "verify-rulepack":
			return rules.RunVerifyRulepack(remaining[1:], stdout, stderr)
		case "completion":
			return completion.RunCompletion(remaining[1:], stdout, stderr)
		case "waive":
			return runWaiveGlobal(remaining[1:], stdout, stderr, gf)
		case "corpus":
			return runCorpusGlobal(remaining[1:], stdout, stderr, gf)
		default:
			first := remaining[0]
			if strings.HasPrefix(first, "-") {
				break
			}
			if looksLikePath(first) {
				break
			}
			fmt.Fprintf(stderr, "unknown command %q\n\n", first)
			fs := flag.NewFlagSet("skeptic", flag.ContinueOnError)
			writeTopLevelUsage(fs, stderr)
			return 2
		}
	}

	mergedArgs := mergeGlobalFlagsIntoArgs(gf, remaining, true)
	_, code := performSkepticRun(mergedArgs, stdout, stderr, scanpkg.ScanWithOptions, skepticRunMode{})
	return code
}

func runVersion(stdout io.Writer) int {
	r := rules.DefaultRules()
	fmt.Fprintf(stdout, "skeptic\n")
	fmt.Fprintf(stdout, "  commit:     %s\n", buildCommit)
	fmt.Fprintf(stdout, "  built:      %s\n", buildDate)
	fmt.Fprintf(stdout, "  go:         %s\n", buildGoVersion)
	fmt.Fprintf(stdout, "  rules:      %d built-in\n", len(r))
	return 0
}

// scanFlagShorthands maps single-char shorthand flag names to their canonical
// long-form name. Used by writeTopLevelUsage and printScanFlags to merge
// short and long forms onto a single help line.
var scanFlagShorthands = map[string]string{
	"f": "format",
	"o": "out",
	"p": "path",
}

func writeTopLevelUsage(fs *flag.FlagSet, out io.Writer) {
	fmt.Fprintln(out, "skeptic - supply chain and agentic threat scanner")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Quick start:")
	fmt.Fprintln(out, "  skeptic init")
	fmt.Fprintln(out, "  skeptic scan")
	fmt.Fprintln(out, "  skeptic scan --preset ci --path .")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Subcommands:")
	fmt.Fprintln(out, "  scan              Scan files for threats (default when no subcommand)")
	fmt.Fprintln(out, "  init              Bootstrap config files and XDG data directory")
	fmt.Fprintln(out, "  config show       Print resolved configuration")
	fmt.Fprintln(out, "  config use <name> Set the active named profile")
	fmt.Fprintln(out, "  corpus            Manage encrypted threat artifact corpus")
	fmt.Fprintln(out, "  ingest            Generate rule packs from threat intel")
	fmt.Fprintln(out, "  serve             Run local daemon scheduler and API")
	fmt.Fprintln(out, "  mcp               Run local MCP server bridge")
	fmt.Fprintln(out, "  waive             Create SHA256-pinned waivers for findings")
	fmt.Fprintln(out, "  bundle            Package binary + rules for distribution")
	fmt.Fprintln(out, "  export-evidence   Export scan findings as signed evidence bundle")
	fmt.Fprintln(out, "  sign-rulepack     Sign external rule packs")
	fmt.Fprintln(out, "  gen-rule-keypair  Generate Ed25519 key pair")
	fmt.Fprintln(out, "  verify-rulepack   Verify rulepack signature")
	fmt.Fprintln(out, "  verify-bundle     Verify signed distribution bundle")
	fmt.Fprintln(out, "  completion        Generate shell completions")
	fmt.Fprintln(out, "  version           Print build info and rule count")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Global flags:")
	fmt.Fprintln(out, "  -v, --verbose N      Verbosity: 0=warn, 1=info, 2=debug, 3=perf")
	fmt.Fprintln(out, "  -q, --quiet          Suppress non-error output")
	fmt.Fprintln(out, "  -c, --config F       Config file (empty = auto-discover .skeptic.*)")
	fmt.Fprintln(out, "      --log-file F     Log file path")
	fmt.Fprintln(out, "      --perf-debug     Enable all profiling + per-file timing")
	fmt.Fprintln(out, "      --cpu-profile F  Write CPU profile to file")
	fmt.Fprintln(out, "      --mem-profile F  Write heap profile on exit")
	fmt.Fprintln(out, "      --trace F        Write execution trace to file")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Scan flags:")
	printScanFlags(fs, out)
}

// printScanFlags writes formatted scan flag help using the shared formatter,
// skipping global flags already shown in the header.
func printScanFlags(fs *flag.FlagSet, out io.Writer) {
	globals := map[string]bool{
		"verbose": true, "quiet": true, "config": true,
		"log-file": true, "perf-debug": true,
		"cpu-profile": true, "mem-profile": true, "trace": true,
	}
	configpkg.PrintFormattedFlags(fs, out, scanFlagShorthands, globals)
}

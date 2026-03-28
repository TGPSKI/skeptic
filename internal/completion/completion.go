package completion

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// Subcommands lists all top-level skeptic subcommand names for shell completion.
var Subcommands = []string{
	"scan", "ingest", "serve", "daemon", "mcp",
	"init", "init-config", "config",
	"corpus", "waive",
	"bundle", "verify-bundle", "export-evidence",
	"sign-rulepack", "gen-rule-keypair", "verify-rulepack",
	"completion", "version",
}

// CorpusSubcommands lists valid corpus subcommand names for shell completion.
var CorpusSubcommands = []string{"init", "fetch", "info", "scan", "purge"}

// ConfigSubcommands lists valid config subcommand names for shell completion.
var ConfigSubcommands = []string{"show", "use"}

// PresetNames lists --preset values for shell completion.
var PresetNames = []string{"quick", "dev", "ci", "hunt", "machine-identity", "ai-workload"}

// FormatNames lists --format values for shell completion.
var FormatNames = []string{"text", "json", "sarif", "markdown"}

// ProfileNames lists --profile values for shell completion.
var ProfileNames = []string{"repo", "developer", "container", "fullfs"}

// ScanStyleNames lists --scan-style values for shell completion.
var ScanStyleNames = []string{"pattern", "behavior", "hybrid"}

// ThreatModeNames lists --threat-mode values for shell completion.
var ThreatModeNames = []string{"all", "machine-identity", "ai-workload"}

// ModeNames lists --mode values for shell completion.
var ModeNames = []string{"developer", "ir", "deep"}

// SeverityNames lists severity level values for --fail-on and related flags.
var SeverityNames = []string{"none", "info", "low", "medium", "high", "critical"}

// RuleQualityNames lists --rule-quality values for shell completion.
var RuleQualityNames = []string{"off", "warn", "strict"}

// IngestFormatNames lists ingest --input-format values for shell completion.
var IngestFormatNames = []string{"auto", "stix", "sigma", "yara"}

// InitFormatNames lists init --format values for shell completion.
var InitFormatNames = []string{"json", "yaml", "env"}

// ShellNames lists shells supported by the completion subcommand.
var ShellNames = []string{"bash", "zsh", "fish"}

// CorpusInfoSortKeys lists corpus info --sort key tokens for shell completion.
var CorpusInfoSortKeys = []string{"name", "size", "date", "source-type", "-name", "-size", "-date", "-source-type"}

// CorpusSourceTypes lists corpus source-type tokens for shell completion.
var CorpusSourceTypes = []string{"url", "file"}

// RunCompletion dispatches the "completion" subcommand, generating shell completions for bash, zsh, or fish.
func RunCompletion(args []string, stdout io.Writer, stderr io.Writer) int {
	fs := flag.NewFlagSet("skeptic completion", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintln(stderr, "usage: skeptic completion <bash|zsh|fish>")
		return 2
	}
	shell := strings.ToLower(strings.TrimSpace(remaining[0]))
	switch shell {
	case "bash":
		GenerateBashCompletion(stdout)
	case "zsh":
		GenerateZshCompletion(stdout)
	case "fish":
		GenerateFishCompletion(stdout)
	default:
		fmt.Fprintf(stderr, "unsupported shell: %s (use bash, zsh, or fish)\n", shell)
		return 2
	}
	return 0
}

func spaced(names []string) string  { return strings.Join(names, " ") }
func parened(names []string) string { return "(" + strings.Join(names, " ") + ")" }

// GenerateBashCompletion writes a bash completion script for skeptic to w.
func GenerateBashCompletion(w io.Writer) {
	fmt.Fprintln(w, `_skeptic() {`)
	fmt.Fprintln(w, `  local cur prev words cword`)
	fmt.Fprintln(w, `  _init_completion || return`)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  local cmds=%q\n", spaced(Subcommands))
	fmt.Fprintf(w, "  local corpus_cmds=%q\n", spaced(CorpusSubcommands))
	fmt.Fprintf(w, "  local config_cmds=%q\n", spaced(ConfigSubcommands))
	fmt.Fprintf(w, "  local presets=%q\n", spaced(PresetNames))
	fmt.Fprintf(w, "  local formats=%q\n", spaced(FormatNames))
	fmt.Fprintf(w, "  local profiles=%q\n", spaced(ProfileNames))
	fmt.Fprintf(w, "  local scan_styles=%q\n", spaced(ScanStyleNames))
	fmt.Fprintf(w, "  local threat_modes=%q\n", spaced(ThreatModeNames))
	fmt.Fprintf(w, "  local modes=%q\n", spaced(ModeNames))
	fmt.Fprintf(w, "  local severities=%q\n", spaced(SeverityNames))
	fmt.Fprintf(w, "  local rule_quality=%q\n", spaced(RuleQualityNames))
	fmt.Fprintf(w, "  local ingest_formats=%q\n", spaced(IngestFormatNames))
	fmt.Fprintf(w, "  local init_formats=%q\n", spaced(InitFormatNames))
	fmt.Fprintf(w, "  local shells=%q\n", spaced(ShellNames))
	fmt.Fprintf(w, "  local corpus_sort_keys=%q\n", spaced(CorpusInfoSortKeys))
	fmt.Fprintf(w, "  local corpus_source_types=%q\n", spaced(CorpusSourceTypes))
	fmt.Fprintln(w)

	// Value completions by flag name
	fmt.Fprintln(w, `  case "$prev" in`)
	fmt.Fprintln(w, `    --preset) COMPREPLY=($(compgen -W "$presets" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --format|-f) COMPREPLY=($(compgen -W "$formats" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --profile) COMPREPLY=($(compgen -W "$profiles" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --scan-style) COMPREPLY=($(compgen -W "$scan_styles" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --threat-mode) COMPREPLY=($(compgen -W "$threat_modes" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --mode) COMPREPLY=($(compgen -W "$modes" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --fail-on) COMPREPLY=($(compgen -W "$severities" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --min-severity) COMPREPLY=($(compgen -W "$severities" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --rule-quality) COMPREPLY=($(compgen -W "$rule_quality" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --input-format) COMPREPLY=($(compgen -W "$ingest_formats" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --sort) COMPREPLY=($(compgen -W "$corpus_sort_keys" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --source-type) COMPREPLY=($(compgen -W "$corpus_source_types" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    --path|-p|--out|-o|--rules-dir|-r|--rules-file|--config|-c|--baseline|--waivers|--log-file)`)
	fmt.Fprintln(w, `      COMPREPLY=($(compgen -f -- "$cur")); return ;;`)
	fmt.Fprintln(w, `  esac`)
	fmt.Fprintln(w)

	// Subcommand dispatch
	fmt.Fprintln(w, `  local subcmd=""`)
	fmt.Fprintln(w, `  for ((i=1; i < cword; i++)); do`)
	fmt.Fprintln(w, `    case "${words[i]}" in`)
	fmt.Fprintln(w, `      -*) ;;`)
	fmt.Fprintln(w, `      *) subcmd="${words[i]}"; break ;;`)
	fmt.Fprintln(w, `    esac`)
	fmt.Fprintln(w, `  done`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, `  if [ -z "$subcmd" ]; then`)
	fmt.Fprintln(w, `    COMPREPLY=($(compgen -W "$cmds" -- "$cur"))`)
	fmt.Fprintln(w, `    return`)
	fmt.Fprintln(w, `  fi`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, `  case "$subcmd" in`)
	fmt.Fprintln(w, `    corpus)`)
	fmt.Fprintln(w, `      if [ "$cword" -eq 2 ] || { [ "$cword" -eq 3 ] && [ "${words[1]}" != "corpus" ]; }; then`)
	fmt.Fprintln(w, `        COMPREPLY=($(compgen -W "$corpus_cmds" -- "$cur"))`)
	fmt.Fprintln(w, `        return`)
	fmt.Fprintln(w, `      fi ;;`)
	fmt.Fprintln(w, `    config)`)
	fmt.Fprintln(w, `      if [ "$cword" -eq 2 ] || { [ "$cword" -eq 3 ] && [ "${words[1]}" != "config" ]; }; then`)
	fmt.Fprintln(w, `        COMPREPLY=($(compgen -W "$config_cmds" -- "$cur"))`)
	fmt.Fprintln(w, `        return`)
	fmt.Fprintln(w, `      fi ;;`)
	fmt.Fprintln(w, `    completion)`)
	fmt.Fprintln(w, `      COMPREPLY=($(compgen -W "$shells" -- "$cur")); return ;;`)
	fmt.Fprintln(w, `    init|init-config)`)
	fmt.Fprintln(w, `      if [ "$prev" = "--format" ] || [ "$prev" = "-f" ]; then`)
	fmt.Fprintln(w, `        COMPREPLY=($(compgen -W "$init_formats" -- "$cur")); return`)
	fmt.Fprintln(w, `      fi ;;`)
	fmt.Fprintln(w, `  esac`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, `  COMPREPLY=($(compgen -f -- "$cur"))`)
	fmt.Fprintln(w, `}`)
	fmt.Fprintln(w, `complete -F _skeptic skeptic`)
}

// GenerateZshCompletion writes a zsh completion script for skeptic to w.
//
//nolint:funlen // declarative shell completion template
func GenerateZshCompletion(w io.Writer) {
	fmt.Fprintln(w, `#compdef skeptic`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, `_skeptic() {`)
	fmt.Fprintln(w, `  local -a cmds corpus_cmds config_cmds`)
	fmt.Fprintf(w, "  cmds=(%s)\n", spaced(Subcommands))
	fmt.Fprintf(w, "  corpus_cmds=(%s)\n", spaced(CorpusSubcommands))
	fmt.Fprintf(w, "  config_cmds=(%s)\n", spaced(ConfigSubcommands))
	fmt.Fprintln(w)
	fmt.Fprintln(w, `  local curcontext="$curcontext" state line`)
	fmt.Fprintln(w)

	// Global flags + first-word subcommand
	fmt.Fprintln(w, `  _arguments -C \`)
	fmt.Fprintln(w, `    '(-v --verbose)'{-v,--verbose}'[verbosity level]:level:(0 1 2 3)' \`)
	fmt.Fprintln(w, `    '(-q --quiet)'{-q,--quiet}'[suppress non-error output]' \`)
	fmt.Fprintln(w, `    '(-c --config)'{-c,--config}'[config file path]:file:_files' \`)
	fmt.Fprintln(w, `    '--log-file[write logs to file]:file:_files' \`)
	fmt.Fprintln(w, `    '--perf-debug[enable all profiling]' \`)
	fmt.Fprintln(w, `    '--cpu-profile[write CPU profile]:file:_files' \`)
	fmt.Fprintln(w, `    '--mem-profile[write heap profile]:file:_files' \`)
	fmt.Fprintln(w, `    '--trace[write execution trace]:file:_files' \`)
	fmt.Fprintf(w, "    '1:command:compadd -a cmds' \\\n")
	fmt.Fprintln(w, `    '*::arg:->args' && return`)
	fmt.Fprintln(w)

	// Per-subcommand flags
	fmt.Fprintln(w, `  case "$line[1]" in`)

	// scan (default)
	fmt.Fprintln(w, `    scan)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintf(w, "        '(-p --path)'{-p,--path}'[scan target]:path:_files' \\\n")
	fmt.Fprintf(w, "        '--paths[comma-separated scan paths]:paths:' \\\n")
	fmt.Fprintf(w, "        '--preset[scan preset]:preset:%s' \\\n", parened(PresetNames))
	fmt.Fprintf(w, "        '(-f --format)'{-f,--format}'[output format]:format:%s' \\\n", parened(FormatNames))
	fmt.Fprintf(w, "        '--profile[scan profile]:profile:%s' \\\n", parened(ProfileNames))
	fmt.Fprintf(w, "        '--scan-style[detection style]:style:%s' \\\n", parened(ScanStyleNames))
	fmt.Fprintf(w, "        '--threat-mode[threat focus]:mode:%s' \\\n", parened(ThreatModeNames))
	fmt.Fprintf(w, "        '--mode[operating mode]:mode:%s' \\\n", parened(ModeNames))
	fmt.Fprintf(w, "        '--fail-on[fail threshold]:severity:%s' \\\n", parened(SeverityNames))
	fmt.Fprintf(w, "        '--rule-quality[quality mode]:mode:%s' \\\n", parened(RuleQualityNames))
	fmt.Fprintln(w, `        '(-o --out)'{-o,--out}'[write report to file]:file:_files' \`)
	fmt.Fprintln(w, `        '--rules-file[external rule JSON files]:file:_files' \`)
	fmt.Fprintln(w, `        '--rules-dir[external rule directory]:dir:_files -/' \`)
	fmt.Fprintln(w, `        '--baseline[prior JSON report]:file:_files' \`)
	fmt.Fprintln(w, `        '--waivers[waiver JSON file]:file:_files' \`)
	fmt.Fprintln(w, `        '--incremental[only scan changed files]' \`)
	fmt.Fprintln(w, `        '--diff-only[emit only new findings]' \`)
	fmt.Fprintln(w, `        '--policy-checks[enable policy checks]' \`)
	fmt.Fprintln(w, `        '--git-correlation[correlate by git author/time]' \`)
	fmt.Fprintln(w, `        '*:file:_files' ;;`)

	// corpus
	fmt.Fprintln(w, `    corpus)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '1:subcommand:compadd -a corpus_cmds' \`)
	fmt.Fprintf(w, "        '(-p --path)'{-p,--path}'[corpus directory]:dir:_files -/' \\\n")
	fmt.Fprintf(w, "        '(-f --format)'{-f,--format}'[output format]:format:%s' \\\n", parened(FormatNames))
	fmt.Fprintf(w, "        '--fail-on[fail threshold]:severity:%s' \\\n", parened(SeverityNames))
	fmt.Fprintf(w, "        '--sort[sort key]:key:%s' \\\n", parened(CorpusInfoSortKeys))
	fmt.Fprintf(w, "        '--source-type[filter by source type]:type:%s' \\\n", parened(CorpusSourceTypes))
	fmt.Fprintln(w, `        '--name[filter by artifact name]:name:' \`)
	fmt.Fprintln(w, `        '--rule[filter by expected rule ID]:rule:' \`)
	fmt.Fprintln(w, `        '--source[filter by source URL/path]:source:' \`)
	fmt.Fprintln(w, `        '(-n --limit)'{-n,--limit}'[max artifacts to show]:count:' \`)
	fmt.Fprintln(w, `        '--offset[skip first N artifacts]:offset:' \`)
	fmt.Fprintln(w, `        '--sha[show full SHA256 hashes]' \`)
	fmt.Fprintln(w, `        '(-o --out)'{-o,--out}'[write output to file]:file:_files' \`)
	fmt.Fprintln(w, `        '(-r --rules-dir)'{-r,--rules-dir}'[rules directory]:dir:_files -/' \`)
	fmt.Fprintln(w, `        '(-s --source)'{-s,--source}'[url or file to fetch]:source:_files' \`)
	fmt.Fprintln(w, `        '(-y --confirm)'{-y,--confirm}'[confirm deletion]' \`)
	fmt.Fprintln(w, `        '*:file:_files' ;;`)

	// config
	fmt.Fprintln(w, `    config)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '1:subcommand:compadd -a config_cmds' \`)
	fmt.Fprintln(w, `        '--json[output as JSON]' \`)
	fmt.Fprintln(w, `        '--system[show only system config]' \`)
	fmt.Fprintln(w, `        '--profile[show only scan profile]' \`)
	fmt.Fprintln(w, `        '*:arg:' ;;`)

	// init
	fmt.Fprintln(w, `    init|init-config)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintf(w, "        '(-f --format)'{-f,--format}'[config format]:format:%s' \\\n", parened(InitFormatNames))
	fmt.Fprintf(w, "        '--preset[starter preset]:preset:%s' \\\n", parened(PresetNames))
	fmt.Fprintln(w, `        '(-o --out)'{-o,--out}'[output path]:file:_files' \`)
	fmt.Fprintln(w, `        '--force[overwrite existing]' ;;`)

	// ingest
	fmt.Fprintln(w, `    ingest)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '(-s --source)'{-s,--source}'[source to ingest]:source:_files' \`)
	fmt.Fprintln(w, `        '(-H --allow-host)'{-H,--allow-host}'[allowed hostname]:host:' \`)
	fmt.Fprintf(w, "        '(-f --input-format)'{-f,--input-format}'[input format]:format:%s' \\\n", parened(IngestFormatNames))
	fmt.Fprintf(w, "        '--min-severity[minimum severity]:severity:%s' \\\n", parened(SeverityNames))
	fmt.Fprintf(w, "        '--rule-quality[quality mode]:mode:%s' \\\n", parened(RuleQualityNames))
	fmt.Fprintln(w, `        '(-o --out)'{-o,--out}'[output rule pack]:file:_files' \`)
	fmt.Fprintln(w, `        '(-n --name)'{-n,--name}'[pack name]:name:' \`)
	fmt.Fprintln(w, `        '--strict[fail if any source unreadable]' \`)
	fmt.Fprintln(w, `        '--generate-tests[emit test stub]' \`)
	fmt.Fprintln(w, `        '*:file:_files' ;;`)

	// serve / daemon
	fmt.Fprintln(w, `    serve|daemon)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '--bind[HTTP listen address]:addr:' \`)
	fmt.Fprintln(w, `        '--scan-interval[schedule interval]:duration:' \`)
	fmt.Fprintln(w, `        '--auth-token[bearer token]:token:' \`)
	fmt.Fprintln(w, `        '--auth-token-file[token file]:file:_files' \`)
	fmt.Fprintln(w, `        '--allow-unauthenticated[disable auth]' \`)
	fmt.Fprintln(w, `        '(-n --dry-run)'{-n,--dry-run}'[print config and exit]' \`)
	fmt.Fprintln(w, `        '--watch[enable fs polling]' \`)
	fmt.Fprintln(w, `        '--run-on-start[initial scan on startup]' \`)
	fmt.Fprintln(w, `        '*:arg:' ;;`)

	// mcp
	fmt.Fprintln(w, `    mcp)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '--daemon-url[daemon URL]:url:' \`)
	fmt.Fprintln(w, `        '--daemon-token[bearer token]:token:' \`)
	fmt.Fprintln(w, `        '--daemon-token-file[token file]:file:_files' \`)
	fmt.Fprintln(w, `        '--auto-daemon[auto-start daemon]' \`)
	fmt.Fprintln(w, `        '--allow-remote-daemon[allow non-loopback]' \`)
	fmt.Fprintln(w, `        '--audit-log[audit log path]:file:_files' \`)
	fmt.Fprintln(w, `        '*:arg:' ;;`)

	// waive
	fmt.Fprintln(w, `    waive)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '(-p --path)'{-p,--path}'[repository path]:path:_files -/' \`)
	fmt.Fprintln(w, `        '--file[file to waive]:file:_files' \`)
	fmt.Fprintln(w, `        '(-r --rule)'{-r,--rule}'[rule ID]:rule:' \`)
	fmt.Fprintln(w, `        '--reason[waiver reason]:reason:' \`)
	fmt.Fprintln(w, `        '(-o --out)'{-o,--out}'[waiver file path]:file:_files' \`)
	fmt.Fprintln(w, `        '*:file:_files' ;;`)

	// bundle
	fmt.Fprintln(w, `    bundle)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '--platform[target os/arch]:platform:' \`)
	fmt.Fprintln(w, `        '--sign[sign bundle]' \`)
	fmt.Fprintln(w, `        '--private-key[signing key]:file:_files' \`)
	fmt.Fprintln(w, `        '(-o --out)'{-o,--out}'[output path]:file:_files' ;;`)

	// verify-bundle
	fmt.Fprintln(w, `    verify-bundle)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '--bundle[bundle path]:file:_files' \`)
	fmt.Fprintln(w, `        '--public-key[public key]:file:_files' ;;`)

	// export-evidence
	fmt.Fprintln(w, `    export-evidence)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '--report[JSON report path]:file:_files' \`)
	fmt.Fprintln(w, `        '(-o --out)'{-o,--out}'[output path]:file:_files' \`)
	fmt.Fprintln(w, `        '--sign[sign bundle]' \`)
	fmt.Fprintln(w, `        '--private-key[signing key]:file:_files' ;;`)

	// sign-rulepack
	fmt.Fprintln(w, `    sign-rulepack)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '--rules-file[rulepack JSON]:file:_files' \`)
	fmt.Fprintln(w, `        '--private-key[signing key]:file:_files' \`)
	fmt.Fprintln(w, `        '--signature-out[signature path]:file:_files' ;;`)

	// verify-rulepack
	fmt.Fprintln(w, `    verify-rulepack)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '--rules-file[rulepack JSON]:file:_files' \`)
	fmt.Fprintln(w, `        '--public-key[public key]:file:_files' ;;`)

	// gen-rule-keypair
	fmt.Fprintln(w, `    gen-rule-keypair)`)
	fmt.Fprintln(w, `      _arguments \`)
	fmt.Fprintln(w, `        '--private-out[private key path]:file:_files' \`)
	fmt.Fprintln(w, `        '--public-out[public key path]:file:_files' ;;`)

	// completion
	fmt.Fprintf(w, "    completion)\n")
	fmt.Fprintf(w, "      _arguments '1:shell:%s' ;;\n", parened(ShellNames))

	fmt.Fprintln(w, `  esac`)
	fmt.Fprintln(w, `}`)
	fmt.Fprintln(w)
	fmt.Fprintln(w, `_skeptic`)
}

// GenerateFishCompletion writes a fish completion script for skeptic to w.
func GenerateFishCompletion(w io.Writer) {
	fmt.Fprintln(w, `# skeptic fish completions`)
	fmt.Fprintln(w)

	// Subcommands (only when no subcommand yet)
	for _, cmd := range Subcommands {
		fmt.Fprintf(w, "complete -c skeptic -n '__fish_use_subcommand' -a %s\n", cmd)
	}
	fmt.Fprintln(w)

	// Global flags
	fmt.Fprintln(w, `# Global flags`)
	fmt.Fprintln(w, `complete -c skeptic -s v -l verbose -d 'verbosity: 0=warn, 1=info, 2=debug, 3=perf'`)
	fmt.Fprintln(w, `complete -c skeptic -s q -l quiet -d 'suppress non-error output'`)
	fmt.Fprintln(w, `complete -c skeptic -s c -l config -rF -d 'config file path'`)
	fmt.Fprintln(w, `complete -c skeptic -l log-file -rF -d 'write logs to file'`)
	fmt.Fprintln(w, `complete -c skeptic -l perf-debug -d 'enable all profiling'`)
	fmt.Fprintln(w)

	// Enum flag values
	fmt.Fprintf(w, "complete -c skeptic -l preset -xa %q\n", spaced(PresetNames))
	fmt.Fprintf(w, "complete -c skeptic -l format -s f -xa %q\n", spaced(FormatNames))
	fmt.Fprintf(w, "complete -c skeptic -l profile -xa %q\n", spaced(ProfileNames))
	fmt.Fprintf(w, "complete -c skeptic -l scan-style -xa %q\n", spaced(ScanStyleNames))
	fmt.Fprintf(w, "complete -c skeptic -l threat-mode -xa %q\n", spaced(ThreatModeNames))
	fmt.Fprintf(w, "complete -c skeptic -l mode -xa %q\n", spaced(ModeNames))
	fmt.Fprintf(w, "complete -c skeptic -l fail-on -xa %q\n", spaced(SeverityNames))
	fmt.Fprintf(w, "complete -c skeptic -l min-severity -xa %q\n", spaced(SeverityNames))
	fmt.Fprintf(w, "complete -c skeptic -l rule-quality -xa %q\n", spaced(RuleQualityNames))
	fmt.Fprintf(w, "complete -c skeptic -l input-format -xa %q\n", spaced(IngestFormatNames))
	fmt.Fprintln(w)

	// File-path flags
	fmt.Fprintln(w, `# File/path flags`)
	fmt.Fprintln(w, `complete -c skeptic -s p -l path -rF -d 'scan target path'`)
	fmt.Fprintln(w, `complete -c skeptic -s o -l out -rF -d 'output file path'`)
	fmt.Fprintln(w, `complete -c skeptic -s r -l rules-dir -rF -d 'rules directory'`)
	fmt.Fprintln(w, `complete -c skeptic -l rules-file -rF -d 'external rule JSON'`)
	fmt.Fprintln(w, `complete -c skeptic -l baseline -rF -d 'baseline JSON report'`)
	fmt.Fprintln(w, `complete -c skeptic -l waivers -rF -d 'waiver JSON file'`)
	fmt.Fprintln(w)

	// Corpus subcommands
	fmt.Fprintln(w, `# corpus subcommands`)
	for _, sub := range CorpusSubcommands {
		fmt.Fprintf(w, "complete -c skeptic -n '__fish_seen_subcommand_from corpus' -a %s\n", sub)
	}
	fmt.Fprintf(w, "complete -c skeptic -n '__fish_seen_subcommand_from corpus' -l sort -xa %q\n", spaced(CorpusInfoSortKeys))
	fmt.Fprintf(w, "complete -c skeptic -n '__fish_seen_subcommand_from corpus' -l source-type -xa %q\n", spaced(CorpusSourceTypes))
	fmt.Fprintln(w, `complete -c skeptic -n '__fish_seen_subcommand_from corpus' -l name -x -d 'filter by artifact name'`)
	fmt.Fprintln(w, `complete -c skeptic -n '__fish_seen_subcommand_from corpus' -l rule -x -d 'filter by expected rule ID'`)
	fmt.Fprintln(w, `complete -c skeptic -n '__fish_seen_subcommand_from corpus' -s n -l limit -x -d 'max artifacts to show'`)
	fmt.Fprintln(w, `complete -c skeptic -n '__fish_seen_subcommand_from corpus' -l offset -x -d 'skip first N artifacts'`)
	fmt.Fprintln(w, `complete -c skeptic -n '__fish_seen_subcommand_from corpus' -l sha -d 'show full SHA256 hashes'`)
	fmt.Fprintln(w)

	// Config subcommands
	fmt.Fprintln(w, `# config subcommands`)
	for _, sub := range ConfigSubcommands {
		fmt.Fprintf(w, "complete -c skeptic -n '__fish_seen_subcommand_from config' -a %s\n", sub)
	}
	fmt.Fprintln(w)

	// completion shell arg
	fmt.Fprintln(w, `# completion shells`)
	for _, sh := range ShellNames {
		fmt.Fprintf(w, "complete -c skeptic -n '__fish_seen_subcommand_from completion' -a %s\n", sh)
	}
}

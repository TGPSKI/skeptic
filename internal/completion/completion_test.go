package completion

import (
	"strings"
	"testing"
)

func TestCompletionBash(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunCompletion([]string{"bash"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "complete -F _skeptic") {
		t.Fatal("bash completion missing complete command")
	}
	for _, want := range []string{
		"corpus", "waive", "scan", "config", "verify-rulepack",
		"corpus_cmds", "config_cmds",
		"--fail-on", "--mode", "--rule-quality",
		"markdown",
		"--sort", "--source-type", "corpus_sort_keys", "corpus_source_types",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("bash completion missing %q", want)
		}
	}
}

func TestCompletionZsh(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunCompletion([]string{"zsh"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "#compdef skeptic") {
		t.Fatal("zsh completion missing compdef")
	}
	for _, want := range []string{
		"corpus)", "config)", "waive)", "ingest)", "serve|daemon)",
		"mcp)", "bundle)", "export-evidence)", "sign-rulepack)",
		"verify-rulepack)", "gen-rule-keypair)", "completion)",
		"--fail-on", "--mode", "--rule-quality",
		"markdown",
		"corpus_cmds", "config_cmds",
		"--sort", "--source-type", "--name", "--rule", "--limit", "--offset", "--sha",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("zsh completion missing %q", want)
		}
	}
}

func TestCompletionFish(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunCompletion([]string{"fish"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	out := stdout.String()
	if !strings.Contains(out, "complete -c skeptic") {
		t.Fatal("fish completion missing complete command")
	}
	for _, want := range []string{
		"corpus", "waive", "scan", "config", "verify-rulepack",
		"__fish_seen_subcommand_from corpus",
		"__fish_seen_subcommand_from config",
		"__fish_seen_subcommand_from completion",
		"fail-on", "mode", "rule-quality",
		"markdown",
		"sort", "source-type", "limit", "offset", "sha",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fish completion missing %q", want)
		}
	}
}

func TestCompletionInvalidShell(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunCompletion([]string{"powershell"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero for invalid shell")
	}
}

func TestCompletionNoArgs(t *testing.T) {
	var stdout, stderr strings.Builder
	code := RunCompletion([]string{}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero for no args")
	}
}

func TestSubcommandsMatchesDispatch(t *testing.T) {
	required := []string{
		"scan", "ingest", "serve", "daemon", "mcp",
		"init", "init-config", "config",
		"corpus", "waive",
		"bundle", "verify-bundle", "export-evidence",
		"sign-rulepack", "gen-rule-keypair", "verify-rulepack",
		"completion", "version",
	}
	set := make(map[string]struct{}, len(Subcommands))
	for _, s := range Subcommands {
		set[s] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; !ok {
			t.Errorf("Subcommands missing %q", r)
		}
	}
}

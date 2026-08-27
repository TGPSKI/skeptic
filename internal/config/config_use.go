package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RunConfigUse sets the active named profile by writing a pointer file.
func RunConfigUse(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		printConfigUseHelp(stderr)
		return 0
	}
	if len(args) == 0 {
		printConfigUseHelp(stderr)
		return 2
	}
	name := strings.TrimSpace(args[0])
	if name == "" {
		fmt.Fprintln(stderr, "profile name must not be empty")
		return 2
	}

	profilePath := filepath.Join(ProfilesDir(), name+".json")
	if _, err := os.Stat(profilePath); err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(stderr, "profile %q not found: %s\n", name, profilePath)
			fmt.Fprintf(stderr, "create it with: skeptic init --out %s\n", profilePath)
			return 2
		}
		fmt.Fprintf(stderr, "cannot read profile: %v\n", err)
		return 1
	}

	pointerPath := filepath.Join(SkepticDataDir(), "active-profile")
	if err := os.MkdirAll(filepath.Dir(pointerPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "failed to create data directory: %v\n", err)
		return 1
	}
	if err := os.WriteFile(pointerPath, []byte(name+"\n"), 0o644); err != nil {
		fmt.Fprintf(stderr, "failed to write active profile pointer: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "active profile: %s (%s)\n", name, profilePath)
	return 0
}

func printConfigUseHelp(out io.Writer) {
	fmt.Fprintln(out, "Usage: skeptic config use <profile-name>")
	fmt.Fprintln(out, "\nSet the active named scan profile.\n\nExamples:\n  skeptic config use ci")
	fmt.Fprintf(out, "\nProfiles directory: %s\n", ProfilesDir())
}

// RunConfig dispatches config sub-subcommands (show, use). Bare invocation prints help.
func RunConfig(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		printConfigHelp(stderr)
		return 0
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	switch sub {
	case "--help", "-h", "help":
		printConfigHelp(stderr)
		return 0
	case "show":
		return RunConfigShow(args[1:], stdout, stderr)
	case "use":
		return RunConfigUse(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown config subcommand: %s\n\n", sub)
		printConfigHelp(stderr)
		return 2
	}
}

func printConfigHelp(w io.Writer) {
	fmt.Fprintln(w, "Usage: skeptic config <show|use> [flags]")
	fmt.Fprintln(w, "\nManage system configuration and named scan profiles.\n\nExamples:\n  skeptic config show --json\n  skeptic config use ci")
	fmt.Fprintln(w, "\nSubcommands:")
	fmt.Fprintln(w, "  show    Print resolved configuration (system + active profile)")
	fmt.Fprintln(w, "  use     Set the active named profile")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Profiles directory: %s\n", ProfilesDir())
	fmt.Fprintf(w, "System config:     %s\n", SystemConfigPath())
}

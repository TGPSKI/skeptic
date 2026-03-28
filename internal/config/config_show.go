package config

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// RunConfigShow prints the fully resolved configuration, annotated with source files.
func RunConfigShow(args []string, stdout io.Writer, stderr io.Writer) int {
	var (
		asJSON      bool
		systemOnly  bool
		profileOnly bool
	)
	fs := flag.NewFlagSet("skeptic config show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&asJSON, "json", false, "output as JSON")
	fs.BoolVar(&systemOnly, "system", false, "show only system config")
	fs.BoolVar(&profileOnly, "profile", false, "show only active scan profile")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if systemOnly && profileOnly {
		fmt.Fprintln(stderr, "--system and --profile are mutually exclusive")
		return 2
	}

	sysConfig, sysPath, sysErr := LoadSystemConfig("")
	if sysErr != nil {
		fmt.Fprintf(stderr, "failed to load system config: %v\n", sysErr)
		return 1
	}

	var profileValues map[string]string
	var profilePath string
	if !systemOnly {
		var loadErr error
		profileValues, profilePath, loadErr = LoadConfigValues("")
		if loadErr != nil {
			fmt.Fprintf(stderr, "failed to load scan config: %v\n", loadErr)
			return 1
		}
	}

	activeProfile, _ := ActiveProfileName()

	if asJSON {
		return showJSON(stdout, stderr, sysConfig, sysPath, profileValues, profilePath, activeProfile, systemOnly, profileOnly)
	}
	return showText(stdout, sysConfig, sysPath, profileValues, profilePath, activeProfile, systemOnly, profileOnly)
}

func showJSON(stdout io.Writer, stderr io.Writer, sys SystemConfig, sysPath string, profile map[string]string, profilePath string, activeName string, systemOnly, profileOnly bool) int {
	out := make(map[string]any)

	if !profileOnly {
		sysMap := map[string]any{
			"path":   sysPath,
			"values": sys,
		}
		out["system"] = sysMap
	}

	if !systemOnly {
		profMap := map[string]any{
			"path":           profilePath,
			"active_profile": activeName,
			"values":         profile,
		}
		out["profile"] = profMap
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "failed to marshal config: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, string(data))
	return 0
}

func showText(stdout io.Writer, sys SystemConfig, sysPath string, profile map[string]string, profilePath string, activeName string, systemOnly, profileOnly bool) int {
	if !profileOnly {
		fmt.Fprintln(stdout, "System config")
		if sysPath != "" {
			fmt.Fprintf(stdout, "  source: %s\n", sysPath)
		} else {
			fmt.Fprintln(stdout, "  source: (defaults, no file)")
		}
		fmt.Fprintf(stdout, "  cache-dir:        %s\n", sys.CacheDir)
		fmt.Fprintf(stdout, "  log-dir:          %s\n", sys.LogDir)
		fmt.Fprintf(stdout, "  daemon-bind:      %s\n", sys.DaemonBind)
		fmt.Fprintf(stdout, "  daemon-token-dir: %s\n", sys.DaemonTokenDir)
		fmt.Fprintf(stdout, "  default-workers:  %d\n", sys.DefaultWorkers)
		if sys.CorpusNoRulepacks {
			fmt.Fprintf(stdout, "  corpus-no-rulepacks: true\n")
		}
		fmt.Fprintln(stdout)
	}

	if !systemOnly {
		fmt.Fprintln(stdout, "Scan profile")
		if activeName != "" {
			fmt.Fprintf(stdout, "  active profile: %s\n", activeName)
		}
		if profilePath != "" {
			fmt.Fprintf(stdout, "  source: %s\n", profilePath)
		} else {
			fmt.Fprintln(stdout, "  source: (none)")
		}
		if len(profile) > 0 {
			keys := make([]string, 0, len(profile))
			for k := range profile {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(stdout, "  %s: %s\n", k, profile[k])
			}
		}
		fmt.Fprintln(stdout)
	}

	if !systemOnly && !profileOnly {
		listProfiles(stdout)
	}
	return 0
}

func listProfiles(stdout io.Writer) {
	dir := ProfilesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".json") {
			names = append(names, strings.TrimSuffix(name, ".json"))
		}
	}
	if len(names) == 0 {
		return
	}
	active, _ := ActiveProfileName() //nolint:errcheck // best-effort active marker for display
	fmt.Fprintln(stdout, "Available profiles")
	fmt.Fprintf(stdout, "  directory: %s\n", dir)
	for _, n := range names {
		marker := "  "
		if n == active {
			marker = "* "
		}
		fmt.Fprintf(stdout, "  %s%s (%s)\n", marker, n, filepath.Join(dir, n+".json"))
	}
}

package config

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// PrintSubcommandHeader writes a consistent usage line, synopsis, and worked
// examples before a subcommand's formatted flags.
func PrintSubcommandHeader(out io.Writer, name, synopsis string, examples []string) {
	fmt.Fprintf(out, "Usage: skeptic %s [flags]\n\n", name)
	fmt.Fprintln(out, synopsis)
	if len(examples) == 0 {
		return
	}
	fmt.Fprintln(out, "\nExamples:")
	for _, example := range examples {
		fmt.Fprintf(out, "  %s\n", example)
	}
	fmt.Fprintln(out, "\nFlags:")
}

// PrintFormattedFlags writes formatted flag help to out, merging shorthand
// and long-form flags onto a single line.
//
// shorthands maps single-char names to their canonical long name
// (e.g. {"f": "format", "p": "path"}).
//
// skipNames is a set of flag names to omit entirely (e.g. globals already
// printed in a header section). Pass nil to skip nothing.
func PrintFormattedFlags(fs *flag.FlagSet, out io.Writer, shorthands map[string]string, skipNames map[string]bool) {
	longToShort := make(map[string]string, len(shorthands))
	for short, long := range shorthands {
		longToShort[long] = short
	}

	fs.VisitAll(func(f *flag.Flag) {
		name := f.Name

		if _, isShort := shorthands[name]; isShort {
			return
		}
		if skipNames[name] {
			return
		}

		var nameCol string
		if short, ok := longToShort[name]; ok {
			nameCol = fmt.Sprintf("  -%s, --%s", short, name)
		} else {
			nameCol = fmt.Sprintf("      --%s", name)
		}

		isBool := f.DefValue == "true" || f.DefValue == "false"
		typeName := flagTypeName(f)
		if !isBool && typeName != "" {
			nameCol += " " + typeName
		}

		usage := f.Usage
		defVal := f.DefValue

		const tabStop = 30
		if len(nameCol) < tabStop {
			pad := strings.Repeat(" ", tabStop-len(nameCol))
			fmt.Fprintf(out, "%s%s%s", nameCol, pad, usage)
		} else {
			fmt.Fprintf(out, "%s\n%s%s", nameCol, strings.Repeat(" ", tabStop), usage)
		}

		if !isBool && defVal != "" && defVal != "0" {
			fmt.Fprintf(out, " (default %s)", defVal)
		} else if isBool && defVal == "true" {
			fmt.Fprintf(out, " (default true)")
		}
		fmt.Fprintln(out)
	})
}

func flagTypeName(f *flag.Flag) string {
	switch f.DefValue {
	case "true", "false":
		return ""
	}
	if g, ok := f.Value.(flag.Getter); ok {
		switch g.Get().(type) {
		case int, int64:
			return "N"
		case float64:
			return "N"
		case string:
			return inferStringMeta(f)
		}
	}
	return ""
}

func inferStringMeta(f *flag.Flag) string {
	n := f.Name
	if strings.HasSuffix(n, "-file") || strings.HasSuffix(n, "-dir") ||
		n == "path" || n == "paths" || n == "sbom" || n == "baseline" ||
		n == "write-baseline" || n == "state-cache" || n == "waivers" ||
		n == "out" || n == "output" ||
		n == "sarif-base-path" ||
		strings.HasSuffix(n, "-manifest") || strings.HasSuffix(n, "-baseline") ||
		strings.HasSuffix(n, "-history") || strings.HasSuffix(n, "-pubkey") {
		return "PATH"
	}
	if n == "include-rules" || n == "exclude-rules" ||
		n == "ignore-paths" || n == "drift-allowed-chains" {
		return "GLOB"
	}
	return "VALUE"
}

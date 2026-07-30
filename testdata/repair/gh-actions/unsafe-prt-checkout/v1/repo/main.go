// Command parsefold flattens nested key: value configuration read on stdin
// into sorted dotted-path lines on stdout.
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// flatten walks indented "key: value" lines and returns dotted paths.
// Two-space indentation nests a key under the previous shallower key.
func flatten(lines []string) []string {
	var out []string
	var stack []string
	for _, raw := range lines {
		trimmed := strings.TrimLeft(raw, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		depth := (len(raw) - len(trimmed)) / 2
		if depth < len(stack) {
			stack = stack[:depth]
		}
		key, value, found := strings.Cut(trimmed, ":")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !found {
			continue
		}
		if value == "" {
			stack = append(stack, key)
			continue
		}
		path := strings.Join(append(append([]string{}, stack...), key), ".")
		out = append(out, fmt.Sprintf("%s=%s", path, value))
	}
	sort.Strings(out)
	return out
}

func main() {
	var lines []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	for _, l := range flatten(lines) {
		fmt.Println(l)
	}
}

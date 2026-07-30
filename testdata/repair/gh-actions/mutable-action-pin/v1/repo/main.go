// Command chronodex indexes timestamped log lines into a per-hour summary.
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// hourOf extracts the "YYYY-MM-DDTHH" prefix of an RFC3339-ish timestamp
// leading a log line, or "" when the line has no recognizable timestamp.
func hourOf(line string) string {
	if len(line) < 13 || line[4] != '-' || line[7] != '-' || line[10] != 'T' {
		return ""
	}
	return line[:13]
}

func main() {
	counts := map[string]int{}
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		if h := hourOf(strings.TrimSpace(sc.Text())); h != "" {
			counts[h]++
		}
	}
	hours := make([]string, 0, len(counts))
	for h := range counts {
		hours = append(hours, h)
	}
	sort.Strings(hours)
	for _, h := range hours {
		fmt.Printf("%s %d\n", h, counts[h])
	}
}

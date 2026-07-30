package main

import "testing"

func TestHourOf(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"2026-07-29T20:41:07Z started", "2026-07-29T20"},
		{"not a timestamp", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := hourOf(c.line); got != c.want {
			t.Errorf("hourOf(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

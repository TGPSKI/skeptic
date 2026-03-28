package scan

import (
	"bytes"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestACMatcherBasic(t *testing.T) {
	m := NewACMatcher([]string{"he", "she", "his", "hers"})
	if m == nil {
		t.Fatal("expected non-nil matcher")
	}
	got := m.Match([]byte("ahishers"))
	want := []string{"his", "she", "he", "hers"}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("len got %d want %d: got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestACMatcherNoMatch(t *testing.T) {
	m := NewACMatcher([]string{"foo", "bar"})
	got := m.Match([]byte("baz qux"))
	if len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}

func TestACMatcherOverlapping(t *testing.T) {
	m := NewACMatcher([]string{"abc", "bc", "c"})
	got := m.Match([]byte("xabcy"))
	want := []string{"abc", "bc", "c"}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestACMatcherEmpty(t *testing.T) {
	if NewACMatcher(nil) != nil {
		t.Fatal("expected nil for nil keywords")
	}
	if NewACMatcher([]string{}) != nil {
		t.Fatal("expected nil for empty keywords")
	}
}

func TestACMatcherMatchAny(t *testing.T) {
	m := NewACMatcher([]string{"alpha", "beta"})
	if !m.MatchAny([]byte("xx alphaxx")) {
		t.Fatal("expected true when pattern present")
	}
	if m.MatchAny([]byte("no match here")) {
		t.Fatal("expected false when absent")
	}
	if NewACMatcher([]string{"x"}).MatchAny(nil) {
		t.Fatal("expected false on nil data")
	}
}

func TestACMatcherLargeInput(t *testing.T) {
	keywords := make([]string, 1200)
	for i := range keywords {
		keywords[i] = strings.Repeat("a", 10) + string(rune('a'+i%26))
	}
	m := NewACMatcher(keywords)
	var buf bytes.Buffer
	for i := 0; i < 100*1024; i++ {
		buf.WriteByte(byte('a' + i%26))
	}
	data := buf.Bytes()
	start := time.Now()
	_ = m.Match(data)
	_ = m.MatchAny(data)
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("large input too slow: %v", elapsed)
	}
}

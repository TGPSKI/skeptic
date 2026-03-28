package rules

import "testing"

func validateRuleSlice(t *testing.T, groupName string, rules []Rule, expectedRuleIDs ...string) {
	t.Helper()
	if len(rules) == 0 {
		t.Fatalf("%s returned no rules", groupName)
	}

	byID := make(map[string]Rule, len(rules))
	for _, rule := range rules {
		if rule.ID == "" {
			t.Fatalf("%s contains rule with empty ID", groupName)
		}
		if rule.Pattern == "" {
			t.Fatalf("%s contains rule %q with empty pattern", groupName, rule.ID)
		}
		if _, exists := byID[rule.ID]; exists {
			t.Fatalf("%s contains duplicate rule ID %q", groupName, rule.ID)
		}
		byID[rule.ID] = rule
	}

	for _, expected := range expectedRuleIDs {
		if _, ok := byID[expected]; !ok {
			t.Fatalf("%s missing expected rule %q", groupName, expected)
		}
	}
}

func assertRuleCount(t *testing.T, groupName string, rules []Rule, want int) {
	t.Helper()
	if len(rules) != want {
		t.Fatalf("%s rule count mismatch: got %d want %d", groupName, len(rules), want)
	}
}

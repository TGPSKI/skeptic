package scan

// ACMatcher implements an Aho-Corasick multi-pattern byte matcher using only the
// standard library. It matches keywords as raw byte sequences (not runes).
type ACMatcher struct {
	root *acNode
}

type acNode struct {
	next map[byte]*acNode
	fail *acNode
	out  []string
}

// NewACMatcher builds an Aho-Corasick automaton from the given keywords.
// Returns nil if keywords is empty.
func NewACMatcher(keywords []string) *ACMatcher {
	if len(keywords) == 0 {
		return nil
	}
	m := &ACMatcher{root: &acNode{}}
	for _, kw := range keywords {
		if kw == "" {
			continue
		}
		m.insert(kw)
	}
	m.buildFailure()
	return m
}

func (m *ACMatcher) insert(word string) {
	n := m.root
	for i := 0; i < len(word); i++ {
		c := word[i]
		if n.next == nil {
			n.next = make(map[byte]*acNode)
		}
		if n.next[c] == nil {
			n.next[c] = &acNode{}
		}
		n = n.next[c]
	}
	n.out = append(n.out, word)
}

func (m *ACMatcher) buildFailure() {
	var q []*acNode
	if m.root.next == nil {
		return
	}
	for _, child := range m.root.next {
		child.fail = m.root
		q = append(q, child)
	}
	for head := 0; head < len(q); head++ {
		u := q[head]
		if u.next == nil {
			continue
		}
		for c, v := range u.next {
			q = append(q, v)
			state := u.fail
			for state != nil && (state.next == nil || state.next[c] == nil) {
				state = state.fail
			}
			if state != nil && state.next != nil && state.next[c] != nil {
				v.fail = state.next[c]
			} else {
				v.fail = m.root
			}
		}
	}
}

// Match returns all keywords found in data. Each keyword appears at most once.
func (m *ACMatcher) Match(data []byte) []string {
	if m == nil || m.root == nil {
		return nil
	}
	seen := make(map[string]struct{})
	state := m.root
	for i := 0; i < len(data); i++ {
		c := data[i]
		for state != m.root && (state.next == nil || state.next[c] == nil) {
			state = state.fail
		}
		if state.next != nil && state.next[c] != nil {
			state = state.next[c]
		} else {
			state = m.root
		}
		for s := state; s != nil; s = s.fail {
			for _, kw := range s.out {
				seen[kw] = struct{}{}
			}
			if s == m.root {
				break
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for kw := range seen {
		out = append(out, kw)
	}
	return out
}

// MatchAny returns true if any keyword appears in data (short-circuits on first match).
func (m *ACMatcher) MatchAny(data []byte) bool {
	if m == nil || m.root == nil {
		return false
	}
	state := m.root
	for i := 0; i < len(data); i++ {
		c := data[i]
		for state != m.root && (state.next == nil || state.next[c] == nil) {
			state = state.fail
		}
		if state.next != nil && state.next[c] != nil {
			state = state.next[c]
		} else {
			state = m.root
		}
		for s := state; s != nil; s = s.fail {
			if len(s.out) > 0 {
				return true
			}
			if s == m.root {
				break
			}
		}
	}
	return false
}

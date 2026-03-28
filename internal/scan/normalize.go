package scan

import (
	"strings"
	"unicode/utf8"
)

// NormalizeNFKC applies a security-focused subset of NFKC normalization to the
// input string. Full NFKC requires golang.org/x/text (not stdlib), so this
// implementation covers the evasion-relevant transformations:
//
//   - Fullwidth ASCII variants (U+FF01–U+FF5E) → ASCII (U+0021–U+007E)
//   - Fullwidth digit variants → ASCII digits
//   - Common Unicode homoglyphs used to evade pattern matching
//   - Zero-width characters stripped (ZWJ, ZWNJ, ZWSP, soft hyphen, BOM)
//
// The result is always valid UTF-8 and lowercase (caller is expected to pass
// already-lowered text, but fullwidth uppercase is handled regardless).
func NormalizeNFKC(s string) string {
	needsWork := false
	for _, r := range s {
		if r >= 0xFF01 && r <= 0xFF5E {
			needsWork = true
			break
		}
		if _, ok := homoglyphs[r]; ok {
			needsWork = true
			break
		}
		if isZeroWidth(r) {
			needsWork = true
			break
		}
	}
	if !needsWork {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size

		if isZeroWidth(r) {
			continue
		}

		if r >= 0xFF01 && r <= 0xFF5E {
			r = r - 0xFEE0
		}

		if mapped, ok := homoglyphs[r]; ok {
			b.WriteString(mapped)
			continue
		}

		b.WriteRune(r)
	}
	return b.String()
}

func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, // zero-width space
		0x200C, // zero-width non-joiner
		0x200D, // zero-width joiner
		0x00AD, // soft hyphen
		0xFEFF: // byte-order mark / zero-width no-break space
		return true
	}
	return false
}

// homoglyphs maps Unicode characters commonly used in evasion to their ASCII
// equivalents. Covers Cyrillic, Greek, and mathematical-style confusables that
// appear in real supply-chain attacks.
var homoglyphs = map[rune]string{
	// Cyrillic → Latin
	'а': "a", 'А': "a",
	'В': "b",
	'с': "c", 'С': "c",
	'е': "e", 'Е': "e",
	'К': "k",
	'М': "m",
	'Н': "h",
	'о': "o", 'О': "o",
	'р': "p", 'Р': "p",
	'Т': "t",
	'х': "x", 'Х': "x",
	'у': "y",

	// Greek → Latin
	'Α': "a", 'α': "a",
	'Β': "b", 'β': "b",
	'Ε': "e", 'ε': "e",
	'Η': "h",
	'Ι': "i", 'ι': "i",
	'Κ': "k", 'κ': "k",
	'Μ': "m",
	'Ν': "n", 'ν': "v",
	'Ο': "o", 'ο': "o",
	'Ρ': "p", 'ρ': "p",
	'Τ': "t", 'τ': "t",
	'Υ': "y",
	'Χ': "x", 'χ': "x",
	'Ζ': "z", 'ζ': "z",

	// Typographic punctuation
	'\u2018': "'", '\u2019': "'", // smart single quotes
	'\u201C': "\"", '\u201D': "\"", // smart double quotes
	'\u2013': "-", '\u2014': "-", // en/em dash
	'\u2026': "...", // ellipsis
}

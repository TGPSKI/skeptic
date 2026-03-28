package scan

import "strconv"

// PolyglotSignature represents a detected binary signature in a text file.
type PolyglotSignature struct {
	Format string // "PE", "ELF", "PDF", "ZIP", "gzip", "PNG", "JFIF"
	Offset int
}

// DetectPolyglot checks a file prefix for multiple binary magic signatures.
// Returns all detected signatures. A text file with binary signatures embedded
// is a potential polyglot attack vector.
//
//nolint:gocyclo // one branch per magic signature is inherent
func DetectPolyglot(data []byte) []PolyglotSignature {
	if len(data) == 0 {
		return nil
	}
	limit := len(data)
	if limit > 8192 {
		limit = 8192
	}
	region := data[:limit]
	seen := make(map[string]struct{})
	var out []PolyglotSignature
	add := func(format string, off int) {
		key := format + ":" + strconv.Itoa(off)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, PolyglotSignature{Format: format, Offset: off})
	}

	for i := 0; i < limit; i++ {
		if i+2 <= limit && region[i] == 0x4D && region[i+1] == 0x5A {
			if i == 0 {
				add("PE", i)
			} else if i+0x40 <= limit {
				lfanew := int(region[i+0x3C]) | int(region[i+0x3D])<<8 |
					int(region[i+0x3E])<<16 | int(region[i+0x3F])<<24
				peOff := i + lfanew
				if lfanew > 0 && lfanew < 1024 && peOff+4 <= limit &&
					region[peOff] == 'P' && region[peOff+1] == 'E' &&
					region[peOff+2] == 0 && region[peOff+3] == 0 {
					add("PE", i)
				}
			}
		}
		if i+4 <= limit && region[i] == 0x7F && region[i+1] == 'E' && region[i+2] == 'L' && region[i+3] == 'F' {
			add("ELF", i)
		}
		if i+4 <= limit && string(region[i:i+4]) == "%PDF" {
			add("PDF", i)
		}
		if i+4 <= limit && region[i] == 0x50 && region[i+1] == 0x4B && region[i+2] == 0x03 && region[i+3] == 0x04 {
			add("ZIP", i)
		}
		if i+2 <= limit && region[i] == 0x1f && region[i+1] == 0x8b {
			add("gzip", i)
		}
		if i+4 <= limit && region[i] == 0x89 && region[i+1] == 'P' && region[i+2] == 'N' && region[i+3] == 'G' {
			add("PNG", i)
		}
		if i+3 <= limit && region[i] == 0xff && region[i+1] == 0xd8 && region[i+2] == 0xff {
			add("JFIF", i)
		}
	}
	return out
}

package model

import "unicode/utf8"

// LooksLikeText reports whether data is valid non-null UTF-8.
func LooksLikeText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return false
		}
	}
	return utf8.Valid(data)
}

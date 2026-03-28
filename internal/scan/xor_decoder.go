package scan

// TryDecodeXORBrute attempts single-byte XOR decoding on high-entropy data.
// It tries all 256 non-zero keys and returns the first result that looks like
// text and contains at least one rule literal hint. Returns nil if no key works.
// Capped at 4 KiB to bound CPU cost.
func TryDecodeXORBrute(data []byte, hintMatcher func([]byte) bool) ([]byte, bool) {
	if len(data) == 0 || hintMatcher == nil {
		return nil, false
	}
	if ShannonEntropy(data) <= 6.5 {
		return nil, false
	}
	work := data
	if len(work) > 4096 {
		work = work[:4096]
	}
	decoded := make([]byte, len(work))
	for k := 1; k <= 255; k++ {
		key := byte(k)
		for i := range work {
			decoded[i] = work[i] ^ key
		}
		if !LooksLikeText(decoded) {
			continue
		}
		if !hintMatcher(decoded) {
			continue
		}
		out := make([]byte, len(decoded))
		copy(out, decoded)
		return out, true
	}
	return nil, false
}

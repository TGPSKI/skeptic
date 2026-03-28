package scan

import "sort"

// EntropyAnomaly represents a region of anomalously high entropy within a file.
type EntropyAnomaly struct {
	Offset         int
	Length         int
	Entropy        float64
	FileAvgEntropy float64
}

// DetectEntropyAnomalies scans content with a sliding window and flags regions
// where local entropy exceeds the file average by more than threshold bits/byte.
// Default window is 256 bytes with 64-byte stride.
func DetectEntropyAnomalies(content []byte, windowSize, stride int, threshold float64) []EntropyAnomaly {
	if len(content) == 0 {
		return nil
	}
	if windowSize <= 0 {
		windowSize = 256
	}
	if stride <= 0 {
		stride = 64
	}
	if threshold <= 0 {
		threshold = 2.0
	}
	fileAvg := ShannonEntropy(content)
	if len(content) < windowSize {
		h := ShannonEntropy(content)
		if h > fileAvg+threshold {
			return []EntropyAnomaly{{
				Offset:         0,
				Length:         len(content),
				Entropy:        h,
				FileAvgEntropy: fileAvg,
			}}
		}
		return nil
	}

	type hit struct {
		start, end int
		entropy    float64
	}
	var hits []hit
	for off := 0; off+windowSize <= len(content); off += stride {
		chunk := content[off : off+windowSize]
		h := ShannonEntropy(chunk)
		if h > fileAvg+threshold {
			hits = append(hits, hit{start: off, end: off + windowSize, entropy: h})
		}
	}
	if len(hits) == 0 {
		return nil
	}

	sort.Slice(hits, func(i, j int) bool { return hits[i].start < hits[j].start })
	var merged []EntropyAnomaly
	cur := hits[0]
	for i := 1; i < len(hits); i++ {
		next := hits[i]
		if next.start <= cur.end {
			if next.end > cur.end {
				cur.end = next.end
			}
			if next.entropy > cur.entropy {
				cur.entropy = next.entropy
			}
			continue
		}
		merged = append(merged, EntropyAnomaly{
			Offset:         cur.start,
			Length:         cur.end - cur.start,
			Entropy:        cur.entropy,
			FileAvgEntropy: fileAvg,
		})
		cur = next
	}
	merged = append(merged, EntropyAnomaly{
		Offset:         cur.start,
		Length:         cur.end - cur.start,
		Entropy:        cur.entropy,
		FileAvgEntropy: fileAvg,
	})
	return merged
}

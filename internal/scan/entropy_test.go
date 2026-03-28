package scan

import (
	"bytes"
	"math"
	"testing"
)

func TestDetectEntropyAnomalies(t *testing.T) {
	// Highly repetitive low-entropy prefix, then random-looking high-entropy tail.
	low := bytes.Repeat([]byte{'a'}, 300)
	high := randomHighEntropyBytes(300)
	content := append(append(low, high...), bytes.Repeat([]byte{'b'}, 300)...)

	anomalies := DetectEntropyAnomalies(content, 256, 64, 2.0)
	if len(anomalies) == 0 {
		t.Fatal("expected at least one entropy anomaly")
	}
	found := false
	for _, a := range anomalies {
		if a.Offset+a.Length > len(low) && a.Offset < len(low)+len(high) {
			found = true
		}
		if a.FileAvgEntropy <= 0 {
			t.Errorf("expected positive file average entropy")
		}
	}
	if !found {
		t.Errorf("expected anomaly overlapping high-entropy region, got %+v", anomalies)
	}
}

// Deterministic pseudo-random high-entropy segment (not crypto-safe; test fixture only).
func randomHighEntropyBytes(n int) []byte {
	out := make([]byte, n)
	x := uint64(0x9e3779b97f4a7c15)
	for i := range out {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = byte(x)
	}
	return out
}

func TestDetectEntropyAnomaliesEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		wantNil bool
	}{
		{"empty", nil, true},
		{"empty_slice", []byte{}, true},
		{"single_byte", []byte{'x'}, true},
		{"all_zero_1024", bytes.Repeat([]byte{0}, 1024), true},
		{"all_same_char_1024", bytes.Repeat([]byte{'a'}, 1024), true},
		{"all_random_1024", randomHighEntropyBytes(1024), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectEntropyAnomalies(tt.content, 256, 64, 2.0)
			if tt.wantNil && len(got) != 0 {
				t.Fatalf("expected nil/empty anomalies, got %+v", got)
			}
		})
	}
	t.Run("shorter_than_window_no_panic", func(t *testing.T) {
		defer func() {
			if err := recover(); err != nil {
				t.Fatalf("panic: %v", err)
			}
		}()
		_ = DetectEntropyAnomalies(randomHighEntropyBytes(50), 256, 64, 2.0)
	})
}

func TestDetectEntropyAnomaliesParameterDefaults(t *testing.T) {
	low := bytes.Repeat([]byte{'a'}, 400)
	high := randomHighEntropyBytes(400)
	content := append(append(low, high...), bytes.Repeat([]byte{'b'}, 400)...)

	gotDefault := DetectEntropyAnomalies(content, 0, 0, 0)
	gotExplicit := DetectEntropyAnomalies(content, 256, 64, 2.0)
	if len(gotDefault) != len(gotExplicit) {
		t.Fatalf("len mismatch: default=%d explicit=%d", len(gotDefault), len(gotExplicit))
	}
	for i := range gotDefault {
		a, b := gotDefault[i], gotExplicit[i]
		if a.Offset != b.Offset || a.Length != b.Length {
			t.Fatalf("idx %d: offset/length mismatch: %+v vs %+v", i, a, b)
		}
		if math.Abs(a.Entropy-b.Entropy) > 1e-9 || math.Abs(a.FileAvgEntropy-b.FileAvgEntropy) > 1e-9 {
			t.Fatalf("idx %d: entropy mismatch: %+v vs %+v", i, a, b)
		}
	}
}

func TestDetectEntropyAnomaliesMerging(t *testing.T) {
	const (
		lowLen    = 3000
		highLen   = 512
		window    = 256
		stride    = 64
		threshold = 2.0
	)
	prefix := bytes.Repeat([]byte{'a'}, lowLen)
	high := randomHighEntropyBytes(highLen)
	suffix := bytes.Repeat([]byte{'b'}, lowLen)
	content := append(append(prefix, high...), suffix...)

	anomalies := DetectEntropyAnomalies(content, window, stride, threshold)
	if len(anomalies) != 1 {
		t.Fatalf("expected exactly 1 merged anomaly, got %d: %+v", len(anomalies), anomalies)
	}
	a := anomalies[0]
	if a.Offset >= lowLen+highLen || a.Offset+a.Length <= lowLen {
		t.Fatalf("expected anomaly to overlap high-entropy block, got offset=%d len=%d", a.Offset, a.Length)
	}
}

func TestShannonEntropyKnownValues(t *testing.T) {
	const eps = 1e-6
	tests := []struct {
		name string
		data []byte
		want float64
	}{
		{"empty", nil, 0},
		{"empty_slice", []byte{}, 0},
		{"single_byte", []byte{'z'}, 0},
		{"repeated_byte", bytes.Repeat([]byte{'x'}, 100), 0},
		{"two_symbols_equal", append(bytes.Repeat([]byte{0}, 512), bytes.Repeat([]byte{255}, 512)...), 1.0},
		{"all_byte_values_once", func() []byte {
			b := make([]byte, 256)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(), 8.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy(tt.data)
			if math.Abs(got-tt.want) > eps {
				t.Fatalf("ShannonEntropy() = %v, want %v", got, tt.want)
			}
		})
	}
}

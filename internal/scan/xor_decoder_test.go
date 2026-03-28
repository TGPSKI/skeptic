package scan

import (
	"bytes"
	"testing"
)

func TestTryDecodeXORBrute(t *testing.T) {
	const key byte = 0x42

	var plain []byte
	plain = append(plain, []byte("hello world")...)
	for b := byte(32); b < 127; b++ {
		plain = append(plain, b)
	}
	for i := 0; len(plain) < 512; i++ {
		plain = append(plain, byte(32+i%95))
	}

	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ key
	}
	if ShannonEntropy(cipher) <= 6.5 {
		t.Fatalf("fixture ciphertext entropy too low for XOR path: %v", ShannonEntropy(cipher))
	}

	out, ok := TryDecodeXORBrute(cipher, func(b []byte) bool {
		return bytes.Contains(b, []byte("hello world"))
	})
	if !ok {
		t.Fatal("expected XOR brute decode with matching hint")
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("decoded mismatch: got len %d want len %d", len(out), len(plain))
	}

	if _, ok := TryDecodeXORBrute(cipher, nil); ok {
		t.Fatal("nil hint matcher should not succeed")
	}

	lowEnt, ok := TryDecodeXORBrute([]byte("hello world"), func([]byte) bool { return true })
	if ok || lowEnt != nil {
		t.Fatal("low-entropy input should return false")
	}
}

func TestTryDecodeXORBruteEdgeCases(t *testing.T) {
	const key byte = 0x37
	buildHighEntropyPlain := func(n int) []byte {
		out := make([]byte, n)
		x := uint64(0xdeadbeefcafebabe)
		for i := range out {
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
			out[i] = 32 + byte(x%95)
		}
		return out
	}
	t.Run("empty_input", func(t *testing.T) {
		out, ok := TryDecodeXORBrute(nil, func([]byte) bool { return true })
		if ok || out != nil {
			t.Fatalf("want nil,false got %v %v", out, ok)
		}
	})
	t.Run("nil_hint_matcher", func(t *testing.T) {
		plain := buildHighEntropyPlain(400)
		cipher := make([]byte, len(plain))
		for i := range plain {
			cipher[i] = plain[i] ^ key
		}
		out, ok := TryDecodeXORBrute(cipher, nil)
		if ok || out != nil {
			t.Fatalf("want nil,false got %v %v", out, ok)
		}
	})
	t.Run("low_entropy_plaintext_like", func(t *testing.T) {
		out, ok := TryDecodeXORBrute([]byte("hello world"), func([]byte) bool { return true })
		if ok || out != nil {
			t.Fatalf("want nil,false got %v %v", out, ok)
		}
	})
	t.Run("exactly_4096_bytes", func(t *testing.T) {
		plain := buildHighEntropyPlain(4096)
		plain = append([]byte("MARK4096"), plain...)
		plain = plain[:4096]
		cipher := make([]byte, len(plain))
		for i := range plain {
			cipher[i] = plain[i] ^ key
		}
		if ShannonEntropy(cipher) <= 6.5 {
			t.Fatal("fixture ciphertext entropy too low")
		}
		out, ok := TryDecodeXORBrute(cipher, func(b []byte) bool {
			return bytes.Contains(b, []byte("MARK4096"))
		})
		if !ok {
			t.Fatal("expected decode for 4096-byte input")
		}
		if !bytes.Equal(out, plain) {
			t.Fatalf("decoded len %d plain len %d", len(out), len(plain))
		}
	})
	t.Run("over_4096_truncates_to_cap", func(t *testing.T) {
		plain := make([]byte, 6000)
		copy(plain, []byte("STARTHINT"))
		for i := 9; i < len(plain); i++ {
			plain[i] = 32 + byte((i*31)%95)
		}
		cipher := make([]byte, len(plain))
		for i := range plain {
			cipher[i] = plain[i] ^ key
		}
		if ShannonEntropy(cipher) <= 6.5 {
			t.Fatal("fixture ciphertext entropy too low")
		}
		out, ok := TryDecodeXORBrute(cipher, func(b []byte) bool {
			return bytes.HasPrefix(b, []byte("STARTHINT"))
		})
		if !ok {
			t.Fatal("expected decode when hint fits in first 4096 bytes")
		}
		if len(out) != 4096 {
			t.Fatalf("want truncated output len 4096, got %d", len(out))
		}
		if !bytes.HasPrefix(out, []byte("STARTHINT")) {
			t.Fatalf("truncated decode missing hint prefix")
		}
	})
}

func TestTryDecodeXORBruteAllKeys(t *testing.T) {
	const key byte = 0xFF
	const marker = "KEY255_UNIQUE_MARKER_XYZ789"
	plain := buildPrintableHighEntropy(2000)
	copy(plain, []byte(marker))
	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ key
	}
	if ShannonEntropy(cipher) <= 6.5 {
		t.Fatalf("fixture ciphertext entropy too low: %v", ShannonEntropy(cipher))
	}
	out, ok := TryDecodeXORBrute(cipher, func(b []byte) bool {
		return bytes.Contains(b, []byte(marker))
	})
	if !ok {
		t.Fatal("expected XOR decode when key 0xFF is the only one that recovers the marker")
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("decoded mismatch")
	}
}

func TestTryDecodeXORBruteLooksLikeTextGating(t *testing.T) {
	const key byte = 0x5A
	const marker = "NULLGATE_UNIQUE_MARKER_ABC12"
	plain := make([]byte, 500)
	copy(plain, []byte(marker))
	plain[80] = 0
	for i := len(marker); i < len(plain); i++ {
		if i == 80 {
			continue
		}
		plain[i] = 32 + byte((i*13)%95)
	}
	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ key
	}
	if ShannonEntropy(cipher) <= 6.5 {
		t.Fatal("fixture ciphertext entropy too low")
	}
	out, ok := TryDecodeXORBrute(cipher, func(b []byte) bool {
		return bytes.Contains(b, []byte(marker))
	})
	if ok || out != nil {
		t.Fatal("decoded buffer with nulls must be rejected by LooksLikeText even when hint would match")
	}
}

func TestTryDecodeXORBruteHintMatcherFalse(t *testing.T) {
	const key byte = 0x42
	plain := buildPrintableHighEntropy(500)
	cipher := make([]byte, len(plain))
	for i := range plain {
		cipher[i] = plain[i] ^ key
	}
	out, ok := TryDecodeXORBrute(cipher, func([]byte) bool { return false })
	if ok || out != nil {
		t.Fatalf("expected no match when hint always false, got ok=%v len=%d", ok, len(out))
	}
}

func buildPrintableHighEntropy(n int) []byte {
	out := make([]byte, n)
	x := uint64(0x9e3779b97f4a7c15)
	for i := range out {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		out[i] = 32 + byte(x%95)
	}
	return out
}

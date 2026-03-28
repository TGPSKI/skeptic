package scan

import "testing"

func FuzzDecodePayloadLayers(f *testing.F) {
	f.Add([]byte("aGVsbG8gd29ybGQ="))
	f.Add([]byte("48656c6c6f"))
	f.Add([]byte("powershell -enc aABlAGwAbABvAA=="))
	f.Add([]byte("hello%20world"))
	f.Add([]byte(`\u0041\u0042\u0043`))
	f.Add([]byte("&amp; &lt; &gt;"))
	f.Add([]byte("uryyb"))
	f.Add([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		layers := DecodePayloadLayers(data)
		for _, layer := range layers {
			if layer.Encoding == "" {
				t.Error("decoded layer with empty encoding label")
			}
			if len(layer.Content) == 0 {
				t.Error("decoded layer with empty content")
			}
		}
	})
}

func FuzzShannonEntropy(f *testing.F) {
	f.Add([]byte("aaaaaaaaaa"))
	f.Add([]byte("abcdefghijklmnop"))
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		h := ShannonEntropy(data)
		if h < 0 {
			t.Errorf("entropy must be non-negative, got %f", h)
		}
		if h > 8.0 {
			t.Errorf("per-byte entropy cannot exceed 8 bits, got %f", h)
		}
		if len(data) == 0 && h != 0 {
			t.Errorf("empty data should have zero entropy, got %f", h)
		}
	})
}

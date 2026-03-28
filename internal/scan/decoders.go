package scan

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"html"
	"io"
	"math"
	"mime/quotedprintable"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/TGPSKI/skeptic/internal/model"
)

// MaxDecodeDepth is the default recursive decode depth limit.
// Use DecodePayloadLayersWithDepth to override per-call.
const MaxDecodeDepth = 3

// DecodedLayer represents one stage of a decoded payload with its encoding label.
type DecodedLayer struct {
	// Encoding is the decoder chain label for this layer (e.g. "base64->gzip").
	Encoding string
	// Content holds the decoded bytes after this layer.
	Content []byte
	// Confidence is the match confidence score by decode depth; shallower decodes score higher.
	Confidence float64 // see confidenceForDecodeDepth
}

// MaxDecodeInputBytes caps the input size for payload layer decoding.
// Encoded payloads worth finding are rarely larger than this.
const MaxDecodeInputBytes = 256 * 1024

// DecodePayloadLayers attempts recursive decoding of raw bytes through multiple encoding schemes.
// Input larger than MaxDecodeInputBytes is truncated to avoid expensive processing on large files.
// Depth is limited by MaxDecodeDepth.
func DecodePayloadLayers(raw []byte) []DecodedLayer {
	return DecodePayloadLayersWithDepth(raw, MaxDecodeDepth)
}

// DecodePayloadLayersWithDepth attempts recursive decoding with a custom maximum recursion depth.
// Values of maxDepth <= 0 are treated as MaxDecodeDepth. Input larger than MaxDecodeInputBytes is truncated.
func DecodePayloadLayersWithDepth(raw []byte, maxDepth int) []DecodedLayer {
	if len(raw) > MaxDecodeInputBytes {
		raw = raw[:MaxDecodeInputBytes]
	}
	if maxDepth <= 0 {
		maxDepth = MaxDecodeDepth
	}
	return decodeRecursive(raw, nil, 0, maxDepth, false)
}

// confidenceForDecodeDepth maps recursion depth to match confidence (shallow decodes score higher).
func confidenceForDecodeDepth(depth int) float64 {
	switch {
	case depth <= 0:
		return 1.0
	case depth == 1:
		return 0.8
	case depth == 2:
		return 0.6
	default:
		return 0.5
	}
}

func decodeRecursive(data []byte, chain []string, depth int, maxDepth int, entropyBonusUsed bool) []DecodedLayer {
	if depth >= maxDepth || len(data) == 0 {
		return nil
	}
	var results []DecodedLayer

	lastDecoder := ""
	if len(chain) > 0 {
		lastDecoder = chain[len(chain)-1]
	}

	decoders := []struct {
		name string
		fn   func([]byte) ([]byte, bool)
	}{
		{"base64", TryDecodeBase64},
		{"hex", TryDecodeHex},
		{"gzip", TryDecodeGzip},
		{"powershell-b64", TryDecodePowerShellEncoded},
		{"url", TryDecodeURL},
		{"unicode", TryDecodeUnicode},
		{"html", TryDecodeHTML},
		{"rot13", TryDecodeROT13},
		{"base32", TryDecodeBase32},
		{"zlib", TryDecodeZlib},
		{"quoted-printable", TryDecodeQuotedPrintable},
		{"pem", TryExtractPEM},
	}

	for _, dec := range decoders {
		if dec.name == lastDecoder {
			continue
		}
		decoded, ok := dec.fn(data)
		if !ok {
			continue
		}
		if !LooksLikeText(decoded) {
			continue
		}
		newChain := append(append([]string{}, chain...), dec.name)
		nextMaxDepth := maxDepth
		nextEntropyBonus := entropyBonusUsed
		if ShannonEntropy(decoded) > 6.0 && !entropyBonusUsed {
			nextMaxDepth = maxDepth + 1
			nextEntropyBonus = true
		}
		results = append(results, DecodedLayer{
			Encoding:   strings.Join(newChain, "->"),
			Content:    decoded,
			Confidence: confidenceForDecodeDepth(depth),
		})
		results = append(results, decodeRecursive(decoded, newChain, depth+1, nextMaxDepth, nextEntropyBonus)...)
	}
	return results
}

// JoinMultilineBase64 joins non-empty lines that contain only base64 alphabet characters.
func JoinMultilineBase64(s string) string {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "\n") {
		return s
	}
	lines := strings.Split(s, "\n")
	var nonempty []string
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t != "" {
			nonempty = append(nonempty, t)
		}
	}
	if len(nonempty) <= 1 {
		return s
	}
	for _, t := range nonempty {
		if !isBase64OnlyLine(t) {
			return s
		}
	}
	return strings.Join(nonempty, "")
}

func isBase64OnlyLine(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			continue
		}
		return false
	}
	return true
}

// TryDecodeBase64 attempts standard, URL-safe, or raw base64 decoding after joining multiline base64 lines.
// It reports false when decoding fails or the decoded bytes equal the input.
func TryDecodeBase64(data []byte) ([]byte, bool) {
	s := JoinMultilineBase64(string(data))
	if len(s) < 4 {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(s)
	}
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, false
	}
	if bytes.Equal(decoded, data) {
		return nil, false
	}
	return decoded, true
}

// TryDecodeGzip decompresses gzip-wrapped data identified by the magic header 0x1f 0x8b.
// It reports false when the input is too short, not gzip, decompression fails, output is empty, or output equals the input.
func TryDecodeGzip(data []byte) ([]byte, bool) {
	if len(data) < 10 {
		return nil, false
	}
	if data[0] != 0x1f || data[1] != 0x8b {
		return nil, false
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	out, err := io.ReadAll(r)
	if err != nil {
		_ = r.Close()
		return nil, false
	}
	if err := r.Close(); err != nil {
		return nil, false
	}
	if len(out) == 0 || bytes.Equal(out, data) {
		return nil, false
	}
	return out, true
}

// TryDecodePowerShellEncoded extracts a PowerShell -EncodedCommand (or -enc) argument, base64-decodes it,
// interprets the payload as UTF-16LE code units, and returns UTF-8 bytes. It reports false when no command is found, decoding fails, or output equals the input.
func TryDecodePowerShellEncoded(data []byte) ([]byte, bool) {
	s := string(data)
	lower := strings.ToLower(s)
	var rest string
	if idx := strings.Index(lower, "-encodedcommand"); idx >= 0 {
		rest = s[idx+len("-encodedcommand"):]
	} else {
		search := 0
		found := -1
		for {
			i := strings.Index(lower[search:], "-enc")
			if i < 0 {
				break
			}
			i += search
			after := i + 4
			if after < len(lower) {
				next := lower[after]
				if next != ' ' && next != '\t' && next != '\r' && next != '\n' {
					search = i + 1
					continue
				}
			}
			if i > 0 {
				prev := lower[i-1]
				if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') || prev == '_' {
					search = i + 1
					continue
				}
			}
			found = i + 4
			break
		}
		if found < 0 {
			return nil, false
		}
		rest = s[found:]
	}
	rest = strings.TrimLeft(rest, " \t\r\n")
	if len(rest) < 4 {
		return nil, false
	}
	end := 0
	for end < len(rest) && rest[end] != ' ' && rest[end] != '\t' && rest[end] != '\r' && rest[end] != '\n' {
		end++
	}
	b64 := rest[:end]
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64)
	}
	if err != nil {
		return nil, false
	}
	if len(raw) < 2 || len(raw)%2 != 0 {
		return nil, false
	}
	u16 := make([]uint16, len(raw)/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	out := string(utf16.Decode(u16))
	if !utf8.ValidString(out) {
		return nil, false
	}
	outb := []byte(out)
	if bytes.Equal(outb, data) {
		return nil, false
	}
	return outb, true
}

// TryDecodeHex attempts hex decoding of trimmed input with even length at least four bytes.
// It reports false when hex decoding fails or output equals the input.
func TryDecodeHex(data []byte) ([]byte, bool) {
	s := strings.TrimSpace(string(data))
	if len(s) < 4 || len(s)%2 != 0 {
		return nil, false
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return nil, false
	}
	if bytes.Equal(decoded, data) {
		return nil, false
	}
	return decoded, true
}

// TryDecodeURL applies URL query unescaping when the input contains percent-encoded bytes.
// It reports false when unescaping fails or the result equals the original string.
func TryDecodeURL(data []byte) ([]byte, bool) {
	s := string(data)
	if !strings.Contains(s, "%") {
		return nil, false
	}
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return nil, false
	}
	if decoded == s {
		return nil, false
	}
	return []byte(decoded), true
}

// TryDecodeUnicode decodes Go-style \\uXXXX and \\UXXXXXXXX escape sequences in the input string.
// It reports false when no escapes are present or nothing changes.
func TryDecodeUnicode(data []byte) ([]byte, bool) {
	s := string(data)
	if !strings.Contains(s, `\u`) && !strings.Contains(s, `\U`) {
		return nil, false
	}
	var b strings.Builder
	changed := false
	i := 0
	for i < len(s) {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
			hexStr := s[i+2 : i+6]
			n, err := parseHexInt(hexStr)
			if err == nil {
				b.WriteRune(rune(n))
				changed = true
				i += 6
				continue
			}
		}
		if i+10 <= len(s) && s[i] == '\\' && s[i+1] == 'U' {
			hexStr := s[i+2 : i+10]
			v, err := strconv.ParseUint(hexStr, 16, 32)
			if err == nil && v <= 0x10ffff {
				b.WriteRune(rune(v))
				changed = true
				i += 10
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	if !changed {
		return nil, false
	}
	return []byte(b.String()), true
}

func parseHexInt(s string) (int, error) {
	var result int
	for _, c := range s {
		result <<= 4
		switch {
		case c >= '0' && c <= '9':
			result |= int(c - '0')
		case c >= 'a' && c <= 'f':
			result |= int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			result |= int(c-'A') + 10
		default:
			return 0, errInvalidHex
		}
	}
	return result, nil
}

var errInvalidHex = &decodeError{"invalid hex character"}

type decodeError struct{ msg string }

// Error returns the decode error message.
func (e *decodeError) Error() string { return e.msg }

// TryDecodeHTML applies HTML entity unescaping when the input contains '&'.
// It reports false when the result is unchanged from the input.
func TryDecodeHTML(data []byte) ([]byte, bool) {
	s := string(data)
	if !strings.Contains(s, "&") {
		return nil, false
	}
	decoded := html.UnescapeString(s)
	if decoded == s {
		return nil, false
	}
	return []byte(decoded), true
}

// TryDecodeBase32 attempts RFC 4648 base32 decoding (standard and hex alphabets).
// Minimum encoded length is 8; identity (output equals input) is rejected.
func TryDecodeBase32(data []byte) ([]byte, bool) {
	s := strings.TrimSpace(string(data))
	if len(s) < 8 {
		return nil, false
	}
	for _, enc := range []*base32.Encoding{base32.StdEncoding, base32.HexEncoding} {
		decoded, err := enc.DecodeString(strings.ToUpper(s))
		if err != nil {
			continue
		}
		if len(decoded) == 0 || bytes.Equal(decoded, data) {
			continue
		}
		return decoded, true
	}
	return nil, false
}

// TryDecodeZlib decompresses zlib-wrapped DEFLATE data (first byte 0x78).
// Empty output and identity are rejected.
func TryDecodeZlib(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	if data[0] != 0x78 {
		return nil, false
	}
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	out, err := io.ReadAll(r)
	if err != nil {
		_ = r.Close()
		return nil, false
	}
	if err := r.Close(); err != nil {
		return nil, false
	}
	if len(out) == 0 || bytes.Equal(out, data) {
		return nil, false
	}
	return out, true
}

// TryDecodeQuotedPrintable decodes MIME quoted-printable content when "=HH" escapes are present.
// Unchanged output is rejected.
func TryDecodeQuotedPrintable(data []byte) ([]byte, bool) {
	if !hasQuotedPrintableHexEscape(data) {
		return nil, false
	}
	r := quotedprintable.NewReader(bytes.NewReader(data))
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, false
	}
	if len(out) == 0 || bytes.Equal(out, data) {
		return nil, false
	}
	return out, true
}

func hasQuotedPrintableHexEscape(data []byte) bool {
	for i := 0; i+2 < len(data); i++ {
		if data[i] != '=' {
			continue
		}
		if isHexByte(data[i+1]) && isHexByte(data[i+2]) {
			return true
		}
	}
	return false
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// TryExtractPEM decodes the first PEM block and returns its DER payload (Bytes field).
// Input must begin (after leading ASCII whitespace) with "-----BEGIN"; otherwise decoding is skipped.
func TryExtractPEM(data []byte) ([]byte, bool) {
	trim := bytes.TrimLeft(data, " \t\r\n")
	if !bytes.HasPrefix(trim, []byte("-----BEGIN")) {
		return nil, false
	}
	block, _ := pem.Decode(trim)
	if block == nil || len(block.Bytes) == 0 {
		return nil, false
	}
	if bytes.Equal(block.Bytes, data) {
		return nil, false
	}
	return block.Bytes, true
}

// TryDecodeROT13 applies the ROT13 cipher to ASCII letters A-Z and a-z; other bytes are unchanged.
// It reports false when the input is shorter than four bytes or the output equals the input.
func TryDecodeROT13(data []byte) ([]byte, bool) {
	if len(data) < 4 {
		return nil, false
	}
	out := make([]byte, len(data))
	for i, b := range data {
		switch {
		case b >= 'A' && b <= 'Z':
			out[i] = (b-'A'+13)%26 + 'A'
		case b >= 'a' && b <= 'z':
			out[i] = (b-'a'+13)%26 + 'a'
		default:
			out[i] = b
		}
	}
	if bytes.Equal(out, data) {
		return nil, false
	}
	return out, true
}

// LooksLikeText reports whether data is valid non-null UTF-8.
// Delegates to model.LooksLikeText; kept here for API compatibility.
func LooksLikeText(data []byte) bool {
	return model.LooksLikeText(data)
}

// EncodingChainString builds an encoding chain label from decoded layers.
func EncodingChainString(layers []DecodedLayer) string {
	if len(layers) == 0 {
		return ""
	}
	return layers[len(layers)-1].Encoding
}

// DefaultEntropyThresholdBits is the default high-entropy cutoff in bits per byte (typical for packed/binary data).
const DefaultEntropyThresholdBits = 6.0

// ShannonEntropy computes per-byte Shannon entropy for the given data.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// IsHighEntropy returns true if data exceeds the given entropy threshold (bits per byte).
// Common callers use DefaultEntropyThresholdBits (6.0) to flag likely encoded or compressed blobs.
func IsHighEntropy(data []byte, threshold float64) bool {
	return ShannonEntropy(data) > threshold
}

// NormalizeUnicode strips zero-width and invisible formatting characters often used to hide homoglyphs
// in identifiers (U+200B, U+200C, U+200D, U+FEFF, U+00AD) and trims surrounding ASCII whitespace.
func NormalizeUnicode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// DetectHomoglyphs checks for mixed-script identifiers that may indicate typosquatting
// (e.g. Latin lookalikes replaced with Cyrillic or Greek letters).
func DetectHomoglyphs(s string) bool {
	var hasLatin, hasCyrillic, hasGreek bool
	for _, r := range s {
		if unicode.Is(unicode.Latin, r) {
			hasLatin = true
		}
		if unicode.Is(unicode.Cyrillic, r) {
			hasCyrillic = true
		}
		if unicode.Is(unicode.Greek, r) {
			hasGreek = true
		}
	}
	if hasLatin && hasCyrillic {
		return true
	}
	if hasLatin && hasGreek {
		return true
	}
	return false
}

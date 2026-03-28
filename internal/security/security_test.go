package security

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactSensitiveText(t *testing.T) {
	knownHash := "822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0"
	input := "token=ghp_abcdefghijklmnopqrstuvwxyz123456 https://user:pass@example.com " + knownHash

	redacted := RedactSensitiveText(input)
	if strings.Contains(redacted, "ghp_abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("expected GitHub token to be redacted: %q", redacted)
	}
	if strings.Contains(redacted, "user:pass@") {
		t.Fatalf("expected basic auth URL to be redacted: %q", redacted)
	}
	if !strings.Contains(redacted, knownHash) {
		t.Fatalf("expected IOC hash to remain visible for analyst context")
	}
}

func TestIsLikelyHash(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "sha1 lower", value: strings.Repeat("a", 40), want: true},
		{name: "sha256 upper", value: strings.Repeat("B", 64), want: true},
		{name: "bad len", value: strings.Repeat("a", 63), want: false},
		{name: "bad char", value: strings.Repeat("g", 64), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLikelyHash(tc.value); got != tc.want {
				t.Fatalf("IsLikelyHash(%q)=%v want %v", tc.value, got, tc.want)
			}
		})
	}
}

func TestNormalizeSHA256(t *testing.T) {
	raw := "SHA256:" + strings.Repeat("A", 64)
	normalized, err := NormalizeSHA256(raw)
	if err != nil {
		t.Fatalf("NormalizeSHA256 returned error: %v", err)
	}
	if normalized != strings.Repeat("a", 64) {
		t.Fatalf("unexpected normalized hash: %s", normalized)
	}

	if _, err := NormalizeSHA256("abc123"); err == nil {
		t.Fatalf("expected invalid short hash to fail")
	}
}

func TestSanitizeMatch(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		redact bool
		want   string
	}{
		{
			name:   "no_redaction",
			value:  "token=ghp_abcdefghijklmnopqrstuvwxyz123456",
			redact: false,
			want:   "token=ghp_abcdefghijklmnopqrstuvwxyz123456",
		},
		{
			name:   "redact_github_token",
			value:  "ghp_abcdefghijklmnopqrstuvwxyz123456",
			redact: true,
		},
		{
			name:   "redact_aws_key",
			value:  "aws_key=AKIAIOSFODNN7EXAMPLE",
			redact: true,
		},
		{
			name:   "preserve_hash",
			value:  strings.Repeat("a", 64),
			redact: true,
			want:   strings.Repeat("a", 64),
		},
		{
			name:   "empty_input",
			value:  "",
			redact: true,
			want:   "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeMatch(tt.value, tt.redact)
			if tt.want != "" {
				if got != tt.want {
					t.Errorf("SanitizeMatch(%q, %v) = %q, want %q", tt.value, tt.redact, got, tt.want)
				}
				return
			}
			if !tt.redact {
				return
			}
			if got == tt.value && tt.value != "" {
				t.Errorf("SanitizeMatch(%q, true) should have redacted, got same value back", tt.value)
			}
		})
	}
}

func TestSHA256FileHex(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "blob.txt")
	content := []byte("skeptic-hash-test")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	got, err := SHA256FileHex(path)
	if err != nil {
		t.Fatalf("SHA256FileHex failed: %v", err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("sha256 mismatch got=%s want=%s", got, want)
	}
}

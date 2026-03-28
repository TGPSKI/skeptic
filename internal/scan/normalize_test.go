package scan

import "testing"

func TestNormalizeNFKC_Fullwidth(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "fullwidth curl",
			input: "\uff43\uff55\uff52\uff4c",
			want:  "curl",
		},
		{
			name:  "fullwidth mixed case",
			input: "\uff23\uff55\uff32\uff4c",
			want:  "CuRl",
		},
		{
			name:  "plain ascii unchanged",
			input: "curl https://example.com",
			want:  "curl https://example.com",
		},
		{
			name:  "zero-width characters stripped",
			input: "c\u200Bur\u200Dl",
			want:  "curl",
		},
		{
			name:  "soft hyphen stripped",
			input: "cu\u00ADrl",
			want:  "curl",
		},
		{
			name:  "cyrillic confusables",
			input: "\u0441\u0443\u0072\u006C",
			want:  "cyrl",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "fullwidth digits",
			input: "\uff11\uff12\uff13",
			want:  "123",
		},
		{
			name:  "mixed fullwidth and ascii",
			input: "run \uff43\uff55\uff52\uff4c http://evil.com",
			want:  "run curl http://evil.com",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeNFKC(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeNFKC(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeNFKC_PassthroughPerformance(t *testing.T) {
	ascii := "this is a normal line of code with no unicode at all"
	got := NormalizeNFKC(ascii)
	if got != ascii {
		t.Errorf("expected passthrough for pure ASCII, got %q", got)
	}
}

func BenchmarkNormalizeNFKC_ASCIIPassthrough(b *testing.B) {
	line := "RUN curl -sSL https://example.com/install.sh | bash"
	for i := 0; i < b.N; i++ {
		NormalizeNFKC(line)
	}
}

func BenchmarkNormalizeNFKC_FullwidthLine(b *testing.B) {
	line := "RUN \uff43\uff55\uff52\uff4c -sSL https://example.com/install.sh | bash"
	for i := 0; i < b.N; i++ {
		NormalizeNFKC(line)
	}
}

package scan

import (
	"strings"
	"testing"
)

func TestDetectPolyglot(t *testing.T) {
	tests := []struct {
		name    string
		prefix  []byte
		formats []string
	}{
		{"PE", []byte{0x4D, 0x5A, 0x90, 0x00}, []string{"PE"}},
		{"ELF", []byte{0x7F, 'E', 'L', 'F', 0x02}, []string{"ELF"}},
		{"PDF", []byte("%PDF-1.4\n"), []string{"PDF"}},
		{"ZIP", []byte{0x50, 0x4B, 0x03, 0x04, 0x0A, 0x00}, []string{"ZIP"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs := DetectPolyglot(tt.prefix)
			if len(sigs) == 0 {
				t.Fatal("expected at least one signature")
			}
			got := make(map[string]struct{})
			for _, s := range sigs {
				got[s.Format] = struct{}{}
			}
			for _, want := range tt.formats {
				if _, ok := got[want]; !ok {
					t.Fatalf("missing format %q in %#v", want, sigs)
				}
			}
		})
	}

	t.Run("plain_text", func(t *testing.T) {
		sigs := DetectPolyglot([]byte("nothing but ordinary prose here"))
		if len(sigs) != 0 {
			t.Fatalf("expected no polyglot signatures for text, got %#v", sigs)
		}
	})

	t.Run("empty", func(t *testing.T) {
		if DetectPolyglot(nil) != nil {
			t.Fatal("empty input should return nil")
		}
	})
}

func TestDetectPolyglotPEValidation(t *testing.T) {
	t.Run("PE at offset 0 always fires", func(t *testing.T) {
		data := []byte{0x4D, 0x5A, 0x90, 0x00}
		sigs := DetectPolyglot(data)
		found := false
		for _, s := range sigs {
			if s.Format == "PE" {
				found = true
			}
		}
		if !found {
			t.Fatal("PE at offset 0 should always fire")
		}
	})

	t.Run("MZ at non-zero offset without valid PE header does not fire", func(t *testing.T) {
		data := make([]byte, 256)
		copy(data, []byte("This is a text file with random bytes "))
		data[50] = 0x4D
		data[51] = 0x5A
		sigs := DetectPolyglot(data)
		for _, s := range sigs {
			if s.Format == "PE" && s.Offset == 50 {
				t.Fatal("MZ at non-zero offset without valid e_lfanew -> PE\\0\\0 should not fire")
			}
		}
	})

	t.Run("MZ at non-zero offset with valid PE header fires", func(t *testing.T) {
		data := make([]byte, 256)
		data[50] = 0x4D
		data[51] = 0x5A
		data[50+0x3C] = 100
		data[50+0x3D] = 0
		data[50+0x3E] = 0
		data[50+0x3F] = 0
		data[50+100] = 'P'
		data[50+101] = 'E'
		data[50+102] = 0
		data[50+103] = 0
		sigs := DetectPolyglot(data)
		found := false
		for _, s := range sigs {
			if s.Format == "PE" && s.Offset == 50 {
				found = true
			}
		}
		if !found {
			t.Fatal("MZ at non-zero offset with valid PE header should fire")
		}
	})
}

func TestDetectPolyglotMultipleMagics(t *testing.T) {
	// Text prefix then embedded ZIP local header
	data := []byte("commentary " + strings.Repeat("x", 20))
	data = append(data, 0x50, 0x4B, 0x03, 0x04)
	sigs := DetectPolyglot(data)
	if len(sigs) == 0 {
		t.Fatal("expected ZIP signature after offset")
	}
	found := false
	for _, s := range sigs {
		if s.Format == "ZIP" && s.Offset > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ZIP at non-zero offset, got %#v", sigs)
	}
}

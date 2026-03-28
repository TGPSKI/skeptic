package main

import (
	"testing"
)

func TestRunVersion(t *testing.T) {
	var buf testWriter
	code := runVersion(&buf)
	if code != 0 {
		t.Fatalf("runVersion returned %d", code)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("runVersion produced no output")
	}
}

type testWriter struct {
	data []byte
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

func (w *testWriter) String() string {
	return string(w.data)
}

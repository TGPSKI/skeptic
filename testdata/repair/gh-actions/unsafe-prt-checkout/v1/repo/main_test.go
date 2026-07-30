package main

import (
	"reflect"
	"testing"
)

func TestFlatten(t *testing.T) {
	in := []string{
		"server:",
		"  host: localhost",
		"  port: 8080",
		"debug: false",
	}
	want := []string{
		"debug=false",
		"server.host=localhost",
		"server.port=8080",
	}
	if got := flatten(in); !reflect.DeepEqual(got, want) {
		t.Errorf("flatten = %v, want %v", got, want)
	}
}

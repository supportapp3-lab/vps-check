package main

import (
	"flag"
	"io"
	"strings"
	"testing"

	"vps-check/internal/model"
)

func TestComposePathsFlag(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var paths composePaths
	fs.Var(&paths, "compose", "Compose path")
	if err := fs.Parse([]string{"--compose", "first.yaml", "--compose", "second.yaml"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "first.yaml,second.yaml" {
		t.Fatalf("unexpected paths: %v", paths)
	}
	if err := paths.Set(" "); err == nil {
		t.Fatal("empty path accepted")
	}
}

func TestFailsThreshold(t *testing.T) {
	tests := []struct {
		status    model.Status
		threshold string
		want      bool
	}{
		{model.HIGH, "high", true},
		{model.WARN, "high", false},
		{model.HIGH, "warn", true},
		{model.WARN, "warn", true},
		{model.INFO, "warn", false},
		{model.SKIP, "warn", false},
		{model.HIGH, "", false},
	}
	for _, tt := range tests {
		if got := failsThreshold(tt.status, tt.threshold); got != tt.want {
			t.Errorf("failsThreshold(%q, %q) = %t, want %t", tt.status, tt.threshold, got, tt.want)
		}
	}
}

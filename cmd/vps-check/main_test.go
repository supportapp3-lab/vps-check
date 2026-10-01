package main

import (
	"testing"

	"vps-check/internal/model"
)

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

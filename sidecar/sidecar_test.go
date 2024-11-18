package sidecar

import (
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"
)

func Test_sleepDuration(t *testing.T) {
	rnd := rand.New(rand.NewSource(int64(time.Now().Nanosecond())))

	tests := []struct {
		name           string
		leaseDuration  time.Duration
		wantRenewAfter time.Duration
	}{
		{"1", 60 * time.Minute, 15 * time.Minute},
		{"2", 30 * time.Minute, 6 * time.Minute},
		{"3", 10 * time.Minute, 2 * time.Minute},
		{"4", 5 * time.Minute, 1 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// values should not be repeated for given duration
			var old []time.Duration
			for i := 0; i < 10; i++ {
				got := sleepDuration(tt.leaseDuration, rnd)
				fmt.Println(got)
				if got < tt.wantRenewAfter || got >= tt.leaseDuration {
					t.Errorf("sleepDuration() = %v, want > %v", got, tt.wantRenewAfter)
				}
				if slices.Contains(old, got) {
					t.Errorf("sleepDuration() = %v, value repeated", got)
				}
				old = append(old, got)
			}
		})
	}
}

package main

import (
	"math/rand"
	"time"
)

// Sleep for 1/3 of the lease duration with a random jitter to discourage syncronised API calls from
// multiple instances of the application
func sleepDuration(leaseDuration time.Duration, rand *rand.Rand) time.Duration {
	return time.Duration((float64(leaseDuration.Nanoseconds()) * 1 / 3) * (rand.Float64() + 1.50) / 2)
}

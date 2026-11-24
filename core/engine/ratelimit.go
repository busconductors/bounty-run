package engine

import (
	"fmt"
	"math"
)

// Rate-limit bounds (requests per second per host) the launchers accept. The
// engine itself takes any float, but +Inf, NaN or a negative value would turn
// into a nonsensical --rate-limit, and below 0.1 req/s a run would take days.
const (
	MinRateLimit = 0.1
	MaxRateLimit = 1000.0
)

// CheckRateLimit accepts 0 (no limit: no flag is emitted) or a finite value in
// [MinRateLimit, MaxRateLimit].
func CheckRateLimit(r float64) error {
	if r == 0 {
		return nil
	}
	if math.IsNaN(r) || math.IsInf(r, 0) || r < MinRateLimit || r > MaxRateLimit {
		return fmt.Errorf("rate limit must be between %g and %g requests per second", MinRateLimit, MaxRateLimit)
	}
	return nil
}

package engine

import (
	"math"
	"testing"
)

func TestCheckRateLimit(t *testing.T) {
	for _, ok := range []float64{0, MinRateLimit, 0.5, 1, 25, MaxRateLimit} {
		if err := CheckRateLimit(ok); err != nil {
			t.Errorf("CheckRateLimit(%v) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []float64{math.Inf(1), math.Inf(-1), math.NaN(), -1, 0.05, MaxRateLimit + 1, 1e300} {
		if err := CheckRateLimit(bad); err == nil {
			t.Errorf("CheckRateLimit(%v) accepted", bad)
		}
	}
}

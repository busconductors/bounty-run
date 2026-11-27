//go:build darwin

package runstore

import "testing"

// A pid spawned *after* the cached ps snapshot is taken is absent from that
// (still-valid, <1s) snapshot. Liveness for a just-launched run must not read
// that as dead: darwin Alive must fall back to a fresh ps for a cache miss.
// Regression guard for F2 (false "engine exited before starting").
func TestAliveFreshFallbackForJustSpawned(t *testing.T) {
	_ = psSnapshot()          // warm the cache so it predates the new pid
	pid := startSleepGroup(t) // spawned after the snapshot: absent from it
	st, err := PIDStart(pid)   // must be a fresh read -> correct start time
	if err != nil {
		t.Fatalf("PIDStart must read a just-spawned pid fresh: %v", err)
	}
	if !Alive(pid, st) {
		t.Error("just-spawned pid (warm-cache miss) must read alive via fresh fallback")
	}
}

//go:build darwin

package runstore

import (
	"syscall"
	"testing"
	"time"
)

// A pid spawned *after* the cached ps snapshot is taken is absent from that
// (still-valid, <1s) snapshot. Liveness for a just-launched run must not read
// that as dead: darwin Alive must fall back to a fresh ps for a cache miss.
// Regression guard for F2 (false "engine exited before starting").
func TestAliveFreshFallbackForJustSpawned(t *testing.T) {
	_ = psSnapshot()          // warm the cache so it predates the new pid
	pid := startSleepGroup(t) // spawned after the snapshot: absent from it
	st, err := PIDStart(pid)  // must be a fresh read -> correct start time
	if err != nil {
		t.Fatalf("PIDStart must read a just-spawned pid fresh: %v", err)
	}
	if !Alive(pid, st) {
		t.Error("just-spawned pid (warm-cache miss) must read alive via fresh fallback")
	}
}

// Once a pid is authoritatively gone, the per-second run-list refresh must not
// fork a fresh ps for it on every tick (a crashed run is a permanent cache
// miss). Alive must memoise the death and stop re-probing. Guards the Finding-1
// per-second fork regression.
func TestAliveMemoizesConfirmedDead(t *testing.T) {
	pid := startSleepGroup(t)
	st, err := PIDStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	// Wait until Alive confirms it gone (snapshot must also age out, <=1s TTL).
	deadline := time.Now().Add(3 * time.Second)
	for Alive(pid, st) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if Alive(pid, st) {
		t.Fatal("killed pid should read dead")
	}
	// Now memoised: further Alive calls must not fork ps again.
	before := freshProbeCount.Load()
	for i := 0; i < 5; i++ {
		if Alive(pid, st) {
			t.Fatal("confirmed-dead pid must stay dead")
		}
	}
	if forks := freshProbeCount.Load() - before; forks != 0 {
		t.Errorf("confirmed-dead Alive re-forked ps %d times; must be memoised (0)", forks)
	}
}

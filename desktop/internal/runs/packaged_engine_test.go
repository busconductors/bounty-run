package runs

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"bountyrun/core/engine"
)

// TestPackagedEngineScan runs a real scan through Service with the frozen
// sidecar, the way the installed app does. It is skipped unless
// BOUNTY_PACKAGED_ENGINE points at a bounty-run executable (for example
// /usr/lib/bounty-run/engine/bounty-run from an extracted package), so
// `go test ./...` stays hermetic. The target is the reserved smoke.invalid.
func TestPackagedEngineScan(t *testing.T) {
	bin := os.Getenv("BOUNTY_PACKAGED_ENGINE")
	if bin == "" {
		t.Skip("BOUNTY_PACKAGED_ENGINE not set")
	}
	s, rec := newTestService(t, bin)
	ref, err := s.StartRun(engine.Options{Target: "smoke.invalid", Intensity: "passive", IPIntelOffline: true, NoTrack: true})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	killOnCleanup(t, s, ref.Dir)
	if _, err := s.Attach(ref.Dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(ref.Dir, "events.jsonl"))
			t.Logf("events:\n%s", b)
			t.Logf("log:\n%s", s.EngineLogTail(ref.Dir, 30))
		}
	}()
	rec.waitFor(t, 4*time.Minute, "dead", func(all []emitted) bool {
		return countChannel(all, "run:"+ref.ID+":dead") > 0
	})
	f, err := os.Open(filepath.Join(ref.Dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var last map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev map[string]any
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			last = ev
		}
	}
	if last == nil || last["type"] != "run_end" {
		t.Fatalf("events.jsonl does not end with run_end: %v", last)
	}
	ents, _ := os.ReadDir(ref.Dir)
	for _, e := range ents {
		t.Logf("run dir: %s", e.Name())
	}
	t.Logf("run_end: %v", last)
}

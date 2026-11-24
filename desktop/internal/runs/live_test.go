package runs

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"bountyrun/core/engine"
)

// liveRun is a paced fake scan: stage a runs to completion with output, a
// progress tick and a finding; stage b runs until the client skips it.
const liveRun = `
import os
start()
emit("stage_start", stage="a")
emit("progress", stage="a", done=1, total=2)
emit("output", stage="a", tool="subfinder", stream="stdout", line="\x1b[31mhost-1.example.com\x1b[0m")
time.sleep(0.4)
emit("finding", severity="high", template="exposed-git", host="dev.example.com",
     url="https://dev.example.com/.git/config", summary="<b>Git</b> repository exposed")
emit("progress", stage="a", done=2, total=2)
emit("stage_end", stage="a", status="ok", duration_ms=400, counts={"hosts": 1})
emit("stage_start", stage="b")
ctl = os.path.join(run_dir, "control")
deadline = time.time() + 10
while time.time() < deadline:
    if os.path.exists(ctl) and "skip b" in open(ctl).read():
        break
    time.sleep(0.05)
emit("stage_end", stage="b", status="skipped", duration_ms=1, counts={})
emit("run_end", status="ok", totals={"high": 1}, report="", summary="")
`

// TestLiveRunStreamsProgress streams a fake run through the real service the
// way the Monitor does (StartRun, Attach, Skip) and checks that progress
// arrives while the run is still going, in order, in the wire shape the
// frontend reducer folds (lib/monitor/store.svelte.js applyBatch).
func TestLiveRunStreamsProgress(t *testing.T) {
	s, rec := newTestService(t, fakeEngine(t, liveRun))
	ref, err := s.StartRun(engine.Options{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, s, ref.Dir)
	if _, err := s.Attach(ref.Dir); err != nil {
		t.Fatal(err)
	}
	batches := func(all []emitted) []Batch { return batchesFor(all, ref.ID) }

	// The first stage is visible before its finding and long before run_end.
	early := batches(rec.waitFor(t, 5*time.Second, "stage_start a", func(all []emitted) bool {
		return hasEvent(batches(all), "stage_start")
	}))
	if hasEvent(early, "finding") || hasEvent(early, "run_end") {
		t.Fatalf("stage_start arrived only with the end of the run: %v", eventTypes(early))
	}

	// The finding arrives while stage b is still running.
	rec.waitFor(t, 5*time.Second, "finding", func(all []emitted) bool { return hasEvent(batches(all), "finding") })
	stageB := func(all []emitted) bool {
		n := 0
		for _, typ := range eventTypes(batches(all)) {
			if typ == "stage_start" {
				n++
			}
		}
		return n == 2
	}
	mid := batches(rec.waitFor(t, 5*time.Second, "stage_start b", stageB))
	if hasEvent(mid, "run_end") {
		t.Fatal("run ended before stage b could be skipped")
	}

	// Skip is acknowledged by stage b's stage_end, as the Monitor expects.
	if err := s.Skip(ref.Dir, "b"); err != nil {
		t.Fatal(err)
	}
	dead := "run:" + ref.ID + ":dead"
	all := rec.waitFor(t, 10*time.Second, "run_end and dead", func(all []emitted) bool {
		return hasEvent(batches(all), "run_end") && countChannel(all, dead) == 1
	})
	got := batches(all)
	want := []string{"run_start", "stage_start", "progress", "finding", "progress", "stage_end", "stage_start", "stage_end", "run_end"}
	if types := eventTypes(got); !slices.Equal(types, want) {
		t.Fatalf("event order = %v, want %v", types, want)
	}
	if len(got) < 3 {
		t.Fatalf("whole run arrived in %d batch(es); want it spread over the run", len(got))
	}
	var skipped, finding map[string]any
	var lines []OutputLine
	for _, b := range got {
		lines = append(lines, b.Output...)
		for _, ev := range b.Events {
			switch {
			case ev["type"] == "stage_end" && ev["stage"] == "b":
				skipped = ev
			case ev["type"] == "finding":
				finding = ev
			}
		}
	}
	if skipped["status"] != "skipped" {
		t.Fatalf("stage b end = %v, want status skipped", skipped)
	}
	if finding["severity"] != "high" || finding["summary"] != "<b>Git</b> repository exposed" {
		t.Fatalf("finding = %v", finding)
	}
	// Tool output travels as sanitized lines, not output events.
	if len(lines) != 1 || lines[0].Line != "host-1.example.com" || lines[0].Tool != "subfinder" || lines[0].Stage != "a" {
		t.Fatalf("output lines = %+v", lines)
	}
	// dead comes last: no batch follows it.
	seenDead := false
	for _, e := range all {
		switch {
		case e.channel == dead:
			seenDead = true
			if st := e.payload.(DeadInfo).Status; st != "ok" {
				t.Fatalf("dead status = %q, want ok", st)
			}
		case seenDead && strings.HasPrefix(e.channel, "run:"+ref.ID):
			t.Fatalf("emission %q after dead", e.channel)
		}
	}

	// The wire shape the reducer reads.
	raw, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"events", "output", "elided", "reset"} {
		if _, ok := wire[key]; !ok {
			t.Fatalf("batch JSON %s lacks %q", raw, key)
		}
	}
}

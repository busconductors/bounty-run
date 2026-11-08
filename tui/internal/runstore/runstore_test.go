package runstore

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func writeRun(t *testing.T, root, target, ts string, pid int, pidStart int64, started int64, lines ...string) string {
	t.Helper()
	d := filepath.Join(root, target, ts)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	rj := fmt.Sprintf(`{"pid":%d,"pgid":%d,"pid_start":%d,"target":%q,"flags":{},"started":%d,"engine_version":"x"}`,
		pid, pid, pidStart, target, started)
	if err := os.WriteFile(filepath.Join(d, "run.json"), []byte(rj), 0o644); err != nil {
		t.Fatal(err)
	}
	var body string
	for _, l := range lines {
		body += l + "\n"
	}
	if len(lines) > 0 {
		if err := os.WriteFile(filepath.Join(d, "events.jsonl"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func only(t *testing.T, root string) Run {
	t.Helper()
	runs, err := Discover(root)
	if err != nil || len(runs) != 1 {
		t.Fatalf("Discover: %v %v", runs, err)
	}
	return runs[0]
}

func TestStatusFromRunEnd(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "a.com", "1", 999999999, 1, 1000,
		`{"v":1,"t":1000,"type":"run_start"}`,
		`{"v":1,"t":6000,"type":"run_end","status":"cancelled","totals":{"high":1}}`)
	r := only(t, root)
	if r.Status != Cancelled || !r.Ended || r.Sev["high"] != 1 || r.Elapsed.Milliseconds() != 5000 {
		t.Fatalf("got %+v", r)
	}
}

func selfStart(t *testing.T) int64 {
	s, err := PIDStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStatusRunningSelf(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "a.com", "1", os.Getpid(), selfStart(t), 1000,
		`{"v":1,"t":1000,"type":"run_start"}`)
	if r := only(t, root); r.Status != Running || ActiveCount([]Run{r}) != 1 {
		t.Fatalf("got %+v", r)
	}
}

func TestStatusCrashedPidReuse(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "a.com", "1", os.Getpid(), selfStart(t)+1, 1000,
		`{"v":1,"t":1000,"type":"run_start"}`)
	if r := only(t, root); r.Status != Crashed {
		t.Fatalf("got %+v", r)
	}
}

func TestSevCountsLive(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "a.com", "1", 999999999, 1, 1000,
		`{"v":1,"t":1,"type":"stage_start","stage":"recon"}`,
		`{"v":1,"t":2,"type":"stage_end","stage":"recon","status":"ok"}`,
		`{"v":1,"t":3,"type":"stage_start","stage":"vuln"}`,
		`{"v":1,"t":4,"type":"finding","severity":"high"}`,
		`{"v":1,"t":5,"type":"finding","severity":"high"}`,
		`{"v":1,"t":6,"type":"finding","severity":"info"}`)
	r := only(t, root)
	if r.Sev["high"] != 2 || r.Sev["info"] != 1 || len(r.Sev) != 2 || r.CurrentStage != "vuln" {
		t.Fatalf("got %+v", r)
	}
}

func TestDiscoverOrder(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "old.com", "1", 999999999, 1, 1000,
		`{"v":1,"t":2000,"type":"run_end","status":"ok","totals":{}}`)
	writeRun(t, root, "new.com", "2", 999999999, 1, 5000,
		`{"v":1,"t":6000,"type":"run_end","status":"failed","totals":{}}`)
	writeRun(t, root, "live.com", "0", os.Getpid(), selfStart(t), 100,
		`{"v":1,"t":100,"type":"run_start"}`)
	os.MkdirAll(filepath.Join(root, "x", "noruns"), 0o755)
	os.WriteFile(filepath.Join(root, "x", "noruns", "run.json"), []byte("{bad"), 0o644)
	runs, err := Discover(root)
	if err != nil || len(runs) != 3 {
		t.Fatalf("%v %v", runs, err)
	}
	got := []string{runs[0].Info.Target, runs[1].Info.Target, runs[2].Info.Target}
	if got[0] != "live.com" || got[1] != "new.com" || got[2] != "old.com" {
		t.Fatalf("order %v", got)
	}
}

func TestIncompatible(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "a.com", "1", 999999999, 1, 1000, `{"v":2,"t":1,"type":"run_start"}`)
	if r := only(t, root); r.Status != Incompatible {
		t.Fatalf("got %+v", r)
	}
}

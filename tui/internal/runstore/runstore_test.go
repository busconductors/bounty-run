package runstore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
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

func startSleepGroup(t *testing.T) int {
	t.Helper()
	c := exec.Command("sleep", "60")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Process.Pid
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	go func() { _ = c.Wait() }()
	return pid
}

func TestGroupHasMemberSince(t *testing.T) {
	g := startSleepGroup(t)
	st, err := PIDStart(g)
	if err != nil {
		t.Fatal(err)
	}
	if !GroupHasMemberSince(g, st) {
		t.Error("member started at since not counted")
	}
	if GroupHasMemberSince(g, st+1) {
		t.Error("member started before since counted")
	}
	if GroupHasMemberSince(999999999, 0) {
		t.Error("nonexistent group has members")
	}
}

func storeOnly(t *testing.T, s *Store) Run {
	t.Helper()
	runs, err := s.Discover()
	if err != nil || len(runs) != 1 {
		t.Fatalf("Discover: %v %v", runs, err)
	}
	return runs[0]
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

func TestStoreEndedRunNotReread(t *testing.T) {
	root := t.TempDir()
	d := writeRun(t, root, "a.com", "1", 999999999, 1, 1000,
		`{"v":1,"t":1000,"type":"run_start"}`,
		`{"v":1,"t":6000,"type":"run_end","status":"cancelled","totals":{"high":1}}`)
	s := NewStore(root)
	if r := storeOnly(t, s); r.Status != Cancelled {
		t.Fatalf("got %+v", r)
	}
	// run_end is final: a rewritten file is not even looked at again.
	if err := os.WriteFile(filepath.Join(d, "events.jsonl"),
		[]byte(`{"v":1,"t":9000,"type":"run_end","status":"failed","totals":{}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := storeOnly(t, s); r.Status != Cancelled || r.Sev["high"] != 1 || r.Elapsed.Milliseconds() != 5000 {
		t.Fatalf("ended run re-derived: %+v", r)
	}
	// A run dir that disappears drops out of the list.
	if err := os.RemoveAll(d); err != nil {
		t.Fatal(err)
	}
	if runs, err := s.Discover(); err != nil || len(runs) != 0 {
		t.Fatalf("removed run still listed: %v %v", runs, err)
	}
}

func TestStoreLiveRunIncremental(t *testing.T) {
	root := t.TempDir()
	d := writeRun(t, root, "a.com", "1", os.Getpid(), selfStart(t), 1000,
		`{"v":1,"t":1000,"type":"run_start"}`,
		`{"v":1,"t":1001,"type":"stage_start","stage":"subs"}`)
	ev := filepath.Join(d, "events.jsonl")
	s := NewStore(root)
	if r := storeOnly(t, s); r.Status != Running || r.CurrentStage != "subs" {
		t.Fatalf("got %+v", r)
	}
	appendFile(t, ev, `{"v":1,"t":1002,"type":"stage_end","stage":"subs","status":"ok"}`+"\n"+
		`{"v":1,"t":1003,"type":"stage_start","stage":"vuln"}`+"\n"+
		`{"v":1,"t":1004,"type":"finding","severity":"high"}`+"\n")
	if r := storeOnly(t, s); r.CurrentStage != "vuln" || r.Sev["high"] != 1 {
		t.Fatalf("appended events not reflected: %+v", r)
	}
	// A half-written last line is held back until it completes, then counted once.
	appendFile(t, ev, `{"v":1,"t":1005,"type":"finding",`)
	if r := storeOnly(t, s); r.Sev["high"] != 1 {
		t.Fatalf("partial line counted: %+v", r)
	}
	appendFile(t, ev, `"severity":"high"}`+"\n")
	r := storeOnly(t, s)
	if r.Sev["high"] != 2 {
		t.Fatalf("completed line not counted once: %+v", r)
	}
	// Returned runs do not share mutable state with the cache.
	r.Sev["high"] = 99
	if r2 := storeOnly(t, s); r2.Sev["high"] != 2 {
		t.Fatalf("cache aliased: %+v", r2)
	}
	appendFile(t, ev, `{"v":1,"t":7000,"type":"run_end","status":"ok","totals":{"high":2}}`+"\n")
	if r := storeOnly(t, s); r.Status != OK || !r.Ended || r.CurrentStage != "" {
		t.Fatalf("run_end not applied: %+v", r)
	}
}

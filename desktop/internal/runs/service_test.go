package runs

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/busconductors/bounty-run/core/engine"
	"github.com/busconductors/bounty-run/core/runstore"
)

const runToEnd = `
start()
emit("stage_start", stage="a")
for i in range(3):
    emit("output", stage="a", tool="t", stream="stdout", line="out %d" % i)
emit("finding", severity="high", template="x", host="h", url="u", summary="s")
emit("stage_end", stage="a", status="ok", duration_ms=1, counts={})
emit("run_end", status="ok", totals={"high": 1}, report="", summary="")
`

func TestConcurrentStartsRespectCap(t *testing.T) {
	// Preflight takes a second, during which a launching engine has no
	// run.json: only the in-flight reservation can keep the fourth one out.
	bin := fakeEngine(t, `
time.sleep(1.0)
start()
time.sleep(60)
`)
	s, _ := newTestService(t, bin)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ok   []RunRef
		errs []error
	)
	gate := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			ref, err := s.StartRun(engine.Options{Target: "example.com"})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			ok = append(ok, ref)
		}()
	}
	close(gate)
	wg.Wait()
	for _, r := range ok {
		killOnCleanup(t, s, r.Dir)
	}
	if len(ok) != MaxActive || len(errs) != 1 {
		t.Fatalf("%d starts succeeded, %d failed (%v); want %d and 1", len(ok), len(errs), errs, MaxActive)
	}
	if !errors.Is(errs[0], ErrCapReached) {
		t.Fatalf("rejected start returned %v, want ErrCapReached", errs[0])
	}
	runs, err := s.ListRuns()
	if err != nil {
		t.Fatal(err)
	}
	if n := runstore.ActiveCount(runs); n != MaxActive {
		t.Fatalf("%d active runs, want %d", n, MaxActive)
	}
	// With the cap reached a later start is refused too, and nothing leaked
	// in the reservation count.
	if _, err := s.StartRun(engine.Options{Target: "example.com"}); !errors.Is(err, ErrCapReached) {
		t.Fatalf("start over cap: %v", err)
	}
	s.mu.Lock()
	launching := s.launching
	s.mu.Unlock()
	if launching != 0 {
		t.Fatalf("launching = %d after all starts returned", launching)
	}
}

func TestDetachDoesNotKillEngine(t *testing.T) {
	bin := fakeEngine(t, `
start()
i = 0
while True:
    emit("output", stage="a", tool="t", stream="stdout", line="tick %d" % i)
    i += 1
    time.sleep(0.02)
`)
	s, rec := newTestService(t, bin)
	ref, err := s.StartRun(engine.Options{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, s, ref.Dir)
	if _, err := s.Attach(ref.Dir); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, 5*time.Second, "a batch", func(all []emitted) bool { return len(batchesFor(all, ref.ID)) > 0 })
	s.Detach(ref.Dir)
	n := len(batchesFor(rec.snapshot(), ref.ID))
	time.Sleep(400 * time.Millisecond)
	if got := len(batchesFor(rec.snapshot(), ref.ID)); got != n {
		t.Fatalf("%d batches emitted after Detach", got-n)
	}
	info, err := runstore.ReadInfo(ref.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if !runstore.Alive(info.PID, info.PIDStart) {
		t.Fatal("engine died on Detach")
	}
	if c := countChannel(rec.snapshot(), "run:"+ref.ID+":dead"); c != 0 {
		t.Fatalf("dead emitted %d times for a live engine", c)
	}
	s.Detach(ref.Dir) // idempotent
}

func TestReattachReplays(t *testing.T) {
	s, rec := newTestService(t, fakeEngine(t, runToEnd))
	ref, err := s.StartRun(engine.Options{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	ended := func(all []emitted) bool { return hasEvent(batchesFor(all, ref.ID), "run_end") }
	snap, err := s.Attach(ref.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if snap.ID != ref.ID || snap.Dir != ref.Dir {
		t.Fatalf("snapshot %+v does not match ref %+v", snap, ref)
	}
	first := batchesFor(rec.waitFor(t, 5*time.Second, "run_end", ended), ref.ID)
	s.Detach(ref.Dir)
	n := len(rec.snapshot())

	if _, err := s.Attach(ref.Dir); err != nil {
		t.Fatal(err)
	}
	all := rec.waitFor(t, 5*time.Second, "replayed run_end", func(all []emitted) bool {
		return len(all) > n && hasEvent(batchesFor(all[n:], ref.ID), "run_end")
	})
	second := batchesFor(all[n:], ref.ID)
	a, b := eventTypes(first), eventTypes(second)
	if strings.Join(a, ",") != strings.Join(b, ",") || b[0] != "run_start" {
		t.Fatalf("replay differs:\nfirst  %v\nsecond %v", a, b)
	}
	var lines []string
	for _, bt := range second {
		for _, o := range bt.Output {
			lines = append(lines, o.Line)
		}
	}
	if strings.Join(lines, "|") != "out 0|out 1|out 2" {
		t.Fatalf("replayed output = %v", lines)
	}
	// Attaching while attached restarts the replay instead of doubling it.
	n = len(rec.snapshot())
	if _, err := s.Attach(ref.Dir); err != nil {
		t.Fatal(err)
	}
	all = rec.waitFor(t, 5*time.Second, "third replay", func(all []emitted) bool {
		return len(all) > n && hasEvent(batchesFor(all[n:], ref.ID), "run_end")
	})
	time.Sleep(200 * time.Millisecond)
	if c := strings.Count(strings.Join(eventTypes(batchesFor(rec.snapshot()[n:], ref.ID)), ","), "run_start"); c != 1 {
		t.Fatalf("run_start replayed %d times after re-Attach", c)
	}
}

func TestExitOneSurfacesFailed(t *testing.T) {
	s, rec := newTestService(t, fakeEngine(t, `
start()
emit("stage_start", stage="a")
emit("run_end", status="failed", totals={}, report="", summary="", error="boom")
sys.exit(1)
`))
	ref, err := s.StartRun(engine.Options{Target: "example.com"})
	if err != nil {
		t.Fatalf("an engine that started must not be a launch error: %v", err)
	}
	if _, err := s.Attach(ref.Dir); err != nil {
		t.Fatal(err)
	}
	dead := "run:" + ref.ID + ":dead"
	all := rec.waitFor(t, 10*time.Second, "dead", func(all []emitted) bool { return countChannel(all, dead) > 0 })
	var info DeadInfo
	for _, e := range all {
		if e.channel == dead {
			info = e.payload.(DeadInfo)
		}
	}
	if info.Status != string(runstore.Failed) {
		t.Fatalf("dead status = %q, want failed", info.Status)
	}
	var endStatus string
	for _, b := range batchesFor(all, ref.ID) {
		for _, ev := range b.Events {
			if ev["type"] == "run_end" {
				endStatus, _ = ev["status"].(string)
			}
		}
	}
	if endStatus != "failed" {
		t.Fatalf("run_end status in batch = %q (dead must follow the final batch)", endStatus)
	}
	if countChannel(all, "runs:changed") == 0 {
		t.Fatal("runs:changed not emitted")
	}
	runs, _ := s.ListRuns()
	if len(runs) != 1 || runs[0].Status != runstore.Failed {
		t.Fatalf("ListRuns = %+v", runs)
	}
	time.Sleep(300 * time.Millisecond)
	if c := countChannel(rec.snapshot(), dead); c != 1 {
		t.Fatalf("dead emitted %d times", c)
	}
}

func TestExitTwoSurfacesLaunchError(t *testing.T) {
	s, _ := newTestService(t, fakeEngine(t, `
sys.stderr.write("usage: bounty-run [-h] target\nbounty-run: error: unrecognized \x1b[31marguments\n")
sys.exit(2)
`))
	_, err := s.StartRun(engine.Options{Target: "example.com"})
	if err == nil {
		t.Fatal("exit 2 before run_start was reported as a successful launch")
	}
	if !errors.Is(err, engine.ErrExited) {
		t.Fatalf("err = %v, want ErrExited", err)
	}
	var le *LaunchError
	if !errors.As(err, &le) {
		t.Fatalf("err %T is not a *LaunchError", err)
	}
	if !strings.Contains(le.Tail, "unrecognized arguments") || strings.Contains(le.Tail, "\x1b") {
		t.Fatalf("log tail = %q", le.Tail)
	}
	if !strings.Contains(err.Error(), "unrecognized arguments") {
		t.Fatalf("error text lacks engine.log tail: %v", err)
	}
	runs, _ := s.ListRuns()
	if len(runs) != 0 {
		t.Fatalf("failed launch listed as a run: %+v", runs)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.launching != 0 {
		t.Fatalf("reservation leaked: launching = %d", s.launching)
	}
}

// runDirWithProc makes root/example.com/<stamp> and a sleeping process that
// leads its own group, like a spawned engine.
func runDirWithProc(t *testing.T, root string) (string, *exec.Cmd) {
	t.Helper()
	dir := filepath.Join(root, "example.com", "20260101-000000")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sleep", "60")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return dir, cmd
}

func runJSON(t *testing.T, pid int) string {
	t.Helper()
	st, err := runstore.PIDStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"pid": %d, "pgid": %d, "pid_start": %d, "target": "example.com", "flags": {}, "started": %d}`,
		pid, pid, st, time.Now().UnixMilli())
}

func TestPartialRunJSONRetried(t *testing.T) {
	s, _ := newTestService(t, "/nonexistent")
	dir, cmd := runDirWithProc(t, s.root)
	full := runJSON(t, cmd.Process.Pid)
	path := filepath.Join(dir, "run.json")
	// The engine writes run.json non-atomically: a reader can see half of it.
	if err := os.WriteFile(path, []byte(full[:len(full)/2]), 0o644); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = os.WriteFile(path, []byte(full), 0o644)
	}()
	if err := s.HardKill(dir); err != nil {
		t.Fatalf("HardKill gave up on a partial run.json: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("process not killed")
	}

	// Attach retries the same way.
	if err := os.WriteFile(path, []byte(full[:10]), 0o644); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(200 * time.Millisecond)
		_ = os.WriteFile(path, []byte(full), 0o644)
	}()
	if _, err := s.Attach(dir); err != nil {
		t.Fatalf("Attach gave up on a partial run.json: %v", err)
	}
	s.Detach(dir)

	// A run.json that never completes is an error, not a hang.
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := s.HardKill(dir); err == nil {
		t.Fatal("HardKill accepted a broken run.json")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("retry took %s", d)
	}
}

func TestSecretsNotInSpawnArgv(t *testing.T) {
	bin := fakeEngine(t, `
dump = {"argv": sys.argv, "cmdline": open("/proc/self/cmdline").read(),
        "proxy": os.environ.get("BOUNTY_RUN_PROXY"),
        "headers": os.environ.get("BOUNTY_RUN_HEADERS"),
        "data": os.environ.get("BOUNTY_RUN_DATA")}
open(os.path.join(run_dir, "dump.json"), "w").write(json.dumps(dump))
start()
emit("run_end", status="ok", totals={}, report="", summary="")
`)
	s, _ := newTestService(t, bin)
	const proxy = "http://user:proxysecret@127.0.0.1:8080"
	const header = "Authorization: Bearer headersecret"
	ref, err := s.StartRun(engine.Options{Target: "Example.COM", Proxy: proxy, Headers: []string{header}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(ref.Dir, "dump.json"))
	if err != nil {
		t.Fatal(err)
	}
	var dump struct {
		Argv           []string
		Cmdline, Data  string
		Proxy, Headers string
	}
	if err := json.Unmarshal(b, &dump); err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(dump.Argv, " ") + " " + dump.Cmdline
	for _, secret := range []string{"proxysecret", "headersecret", "Authorization"} {
		if strings.Contains(argv, secret) {
			t.Fatalf("secret %q in engine argv: %s", secret, argv)
		}
	}
	if dump.Proxy != proxy || !strings.Contains(dump.Headers, "headersecret") {
		t.Fatalf("secrets did not reach the engine environment: %+v", dump)
	}
	if dump.Data != s.root {
		t.Fatalf("BOUNTY_RUN_DATA = %q, want %q", dump.Data, s.root)
	}
	if dump.Argv[1] != "example.com" {
		t.Fatalf("target not normalized: %q", dump.Argv[1])
	}
	if !strings.HasPrefix(ref.Dir, filepath.Join(s.root, "example.com")+"/") {
		t.Fatalf("run dir %q not under the outputs root", ref.Dir)
	}
}

func TestStartRunRejectsBadInput(t *testing.T) {
	s, _ := newTestService(t, "/nonexistent")
	if _, err := s.StartRun(engine.Options{Target: "not a domain"}); err == nil {
		t.Fatal("invalid target accepted")
	}
	if _, err := s.StartRun(engine.Options{Target: "example.com", Proxy: "ftp://x"}); err == nil {
		t.Fatal("invalid proxy accepted")
	}
	for _, rl := range []float64{math.Inf(1), math.NaN(), -1, 0.01, 1e6} {
		if _, err := s.StartRun(engine.Options{Target: "example.com", RateLimit: rl}); err == nil || !strings.Contains(err.Error(), "rate limit") {
			t.Fatalf("rate limit %v: err = %v, want a rate limit error", rl, err)
		}
	}
	if _, err := s.StartRun(engine.Options{Target: "example.com"}); err == nil {
		t.Fatal("missing engine binary accepted")
	}
	if entries, _ := os.ReadDir(s.root); len(entries) != 0 {
		t.Fatalf("rejected starts left %d entries in the outputs root", len(entries))
	}
}

func TestControlsConfinedToOutputsRoot(t *testing.T) {
	s, _ := newTestService(t, "/nonexistent")
	outside := t.TempDir()
	for _, dir := range []string{
		outside,
		filepath.Join(s.root, "example.com"),
		filepath.Join(s.root, "example.com", "x", "y"),
		filepath.Join(s.root, "..", "x", "y"),
		"relative/dir",
	} {
		if err := s.Cancel(dir); err == nil {
			t.Errorf("Cancel(%q) accepted", dir)
		}
		if _, err := s.Attach(dir); err == nil {
			t.Errorf("Attach(%q) accepted", dir)
		}
		if err := s.HardKill(dir); err == nil {
			t.Errorf("HardKill(%q) accepted", dir)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "control")); err == nil {
		t.Fatal("control file written outside the outputs root")
	}
	dir := filepath.Join(s.root, "example.com", "20260101-000000")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Skip(dir, "nuclei\ncancel"); err == nil {
		t.Fatal("stage with a newline accepted: it would inject a control line")
	}
	if err := s.Skip(dir, "nuclei"); err != nil {
		t.Fatal(err)
	}
	if err := s.Cancel(dir); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "control"))
	if string(b) != "skip nuclei\ncancel\n" {
		t.Fatalf("control = %q", b)
	}
}

func TestEngineLogTailSanitized(t *testing.T) {
	s, _ := newTestService(t, "/nonexistent")
	dir := filepath.Join(s.root, "example.com", "20260101-000000")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for i := range 50 {
		fmt.Fprintf(&b, "line %d \x1b[31mred\x1b[0m\x07\n", i)
	}
	if err := os.WriteFile(filepath.Join(dir, "engine.log"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	got := s.EngineLogTail(dir, 3)
	if got != "line 47 red\nline 48 red\nline 49 red" {
		t.Fatalf("tail = %q", got)
	}
	if got := s.EngineLogTail("/etc", 3); got != "" {
		t.Fatalf("tail outside root = %q", got)
	}
}

// replayEmitter keeps no payloads, so memory measured is the service's own.
// It records what the replay tests assert on: ordering of dead against the
// batches, batch sizes, and how many findings arrived and how long their
// fields were.
type replayEmitter struct {
	delay time.Duration // per batch: a slow client

	mu            sync.Mutex
	batches       int
	findings      int
	maxBatchBytes int
	maxField      int
	runEnd        bool
	dead          int
	batchesAtDead int
	runEndAtDead  bool
	deadCh        chan struct{}
	once          sync.Once
}

func newReplayEmitter(delay time.Duration) *replayEmitter {
	return &replayEmitter{delay: delay, deadCh: make(chan struct{})}
}

func (c *replayEmitter) Emit(channel string, payload any) {
	switch p := payload.(type) {
	case DeadInfo:
		c.mu.Lock()
		c.dead++
		c.batchesAtDead, c.runEndAtDead = c.batches, c.runEnd
		c.mu.Unlock()
		c.once.Do(func() { close(c.deadCh) })
	case Batch:
		if c.delay > 0 {
			time.Sleep(c.delay)
		}
		j, err := json.Marshal(p)
		if err != nil {
			panic(err)
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.batches++
		c.maxBatchBytes = max(c.maxBatchBytes, len(j))
		for _, ev := range p.Events {
			switch ev["type"] {
			case "run_end":
				c.runEnd = true
			case "finding":
				c.findings++
			}
			for _, k := range []string{"summary", "msg", "url"} {
				if v, ok := ev[k].(string); ok {
					c.maxField = max(c.maxField, len(v))
				}
			}
		}
	}
}

// replay writes events.jsonl with write for a run whose engine is gone
// (pid 0), attaches, and waits for run:<id>:dead. It returns the emitter and
// the peak heap growth during the replay.
func replay(t *testing.T, em *replayEmitter, write func(w *bufio.Writer)) int64 {
	t.Helper()
	root := filepath.Join(t.TempDir(), "outputs")
	dir := filepath.Join(root, "example.com", "20260101-000000")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.json"), []byte(`{"pid":0,"pgid":0,"pid_start":0,"target":"example.com","flags":{},"started":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	write(w)
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New(Config{Root: root, EngineBin: "/nonexistent", Emitter: em, LivenessInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	peak := base
	if _, err := s.Attach(dir); err != nil {
		t.Fatal(err)
	}
	timeout := time.After(120 * time.Second)
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
loop:
	for {
		select {
		case <-em.deadCh:
			break loop
		case <-timeout:
			t.Fatal("replay did not end with run:<id>:dead")
		case <-tick.C:
			runtime.ReadMemStats(&ms)
			peak = max(peak, ms.HeapAlloc)
		}
	}
	time.Sleep(300 * time.Millisecond) // anything after dead would show up now
	s.Detach(dir)

	em.mu.Lock()
	defer em.mu.Unlock()
	if !em.runEndAtDead {
		t.Errorf("dead emitted before the run_end batch (after %d batches)", em.batchesAtDead)
	}
	if em.batches != em.batchesAtDead || em.dead != 1 {
		t.Errorf("%d batches after dead; dead emitted %d times", em.batches-em.batchesAtDead, em.dead)
	}
	return int64(peak) - int64(base)
}

func TestReplay128MiBBoundedMemory(t *testing.T) {
	const size = 128 << 20
	em := newReplayEmitter(0)
	growth := replay(t, em, func(w *bufio.Writer) {
		pad := strings.Repeat("x", 4000)
		fmt.Fprintln(w, `{"v":1,"t":1,"type":"run_start","target":"example.com","flags":{},"stages":["a"]}`)
		fmt.Fprintln(w, `{"v":1,"t":1,"type":"stage_start","stage":"a"}`)
		written, i := 0, 0
		for written < size {
			n, _ := fmt.Fprintf(w, `{"v":1,"t":2,"type":"output","stage":"a","tool":"t","stream":"stdout","line":"%d %s"}`+"\n", i, pad)
			written += n
			if i%50 == 0 {
				n, _ = fmt.Fprintf(w, `{"v":1,"t":2,"type":"progress","stage":"a","done":%d,"total":1}`+"\n", i)
				written += n
			}
			if i%500 == 0 {
				n, _ = fmt.Fprintf(w, `{"v":1,"t":2,"type":"finding","severity":"info","template":"t%d","host":"h","url":"u","summary":"s"}`+"\n", i)
				written += n
			}
			i++
		}
		fmt.Fprintln(w, `{"v":1,"t":3,"type":"run_end","status":"ok","totals":{},"report":"","summary":""}`)
	})
	t.Logf("replayed %d MiB in %d batches; heap growth peak %.1f MiB", size>>20, em.batches, float64(growth)/(1<<20))
	if growth >= 64<<20 {
		t.Fatalf("heap grew %.1f MiB during replay, limit 64 MiB", float64(growth)/(1<<20))
	}
}

// Engine event lines can carry ~1 MiB strings (log msg, finding summary).
// Structural events are never dropped, so they must be bounded by size: cut
// for display and flushed by pending bytes, even with a slow client.
func TestReplayHugeStructuralLinesBounded(t *testing.T) {
	const n = 48                         // ~1 MiB lines each; few, since decoding them is slow under -race
	huge := strings.Repeat("é", 512<<10) // 1 MiB of UTF-8
	em := newReplayEmitter(5 * time.Millisecond)
	growth := replay(t, em, func(w *bufio.Writer) {
		fmt.Fprintln(w, `{"v":1,"t":1,"type":"run_start","target":"example.com","flags":{},"stages":["a"]}`)
		for i := range n {
			if i%2 == 0 {
				fmt.Fprintf(w, `{"v":1,"t":2,"type":"finding","severity":"high","template":"t%d","host":"h","url":"%s","summary":"%s"}`+"\n", i, huge, huge)
			} else {
				fmt.Fprintf(w, `{"v":1,"t":2,"type":"log","level":"info","msg":"%s"}`+"\n", huge)
			}
		}
		fmt.Fprintln(w, `{"v":1,"t":3,"type":"run_end","status":"ok","totals":{},"report":"","summary":""}`)
	})
	t.Logf("heap growth peak %.1f MiB; largest batch %.1f MiB in %d batches", float64(growth)/(1<<20), float64(em.maxBatchBytes)/(1<<20), em.batches)
	if em.findings != n/2 {
		t.Fatalf("%d findings delivered, want %d", em.findings, n/2)
	}
	if em.maxField > MaxLineBytes {
		t.Fatalf("a structural field of %d bytes reached the client, limit %d", em.maxField, MaxLineBytes)
	}
	if limit := FlushBytes + 1<<20; em.maxBatchBytes > limit {
		t.Fatalf("batch of %d bytes, limit %d", em.maxBatchBytes, limit)
	}
	if growth >= 64<<20 {
		t.Fatalf("heap grew %.1f MiB during replay, limit 64 MiB", float64(growth)/(1<<20))
	}
}

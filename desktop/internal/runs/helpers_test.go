package runs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// emitted is one Emit call.
type emitted struct {
	channel string
	payload any
}

// recorder is a goroutine-safe bridge.Emitter that keeps every emission.
type recorder struct {
	mu     sync.Mutex
	all    []emitted
	notify chan struct{}
}

func newRecorder() *recorder { return &recorder{notify: make(chan struct{}, 1)} }

func (r *recorder) Emit(channel string, payload any) {
	r.mu.Lock()
	r.all = append(r.all, emitted{channel, payload})
	r.mu.Unlock()
	select {
	case r.notify <- struct{}{}:
	default:
	}
}

func (r *recorder) snapshot() []emitted {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]emitted(nil), r.all...)
}

// waitFor polls until cond holds over the recorded emissions or the timeout
// passes, returning the emissions it last saw.
func (r *recorder) waitFor(t *testing.T, timeout time.Duration, what string, cond func([]emitted) bool) []emitted {
	t.Helper()
	deadline := time.After(timeout)
	for {
		all := r.snapshot()
		if cond(all) {
			return all
		}
		select {
		case <-r.notify:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("timed out waiting for %s; got %d emissions", what, len(all))
		}
	}
}

// batches returns the Batch payloads emitted on run:<id>:batch, in order.
func batchesFor(all []emitted, id string) []Batch {
	var out []Batch
	for _, e := range all {
		if e.channel == "run:"+id+":batch" {
			out = append(out, e.payload.(Batch))
		}
	}
	return out
}

func eventTypes(bs []Batch) []string {
	var out []string
	for _, b := range bs {
		for _, ev := range b.Events {
			out = append(out, ev["type"].(string))
		}
	}
	return out
}

func hasEvent(bs []Batch, typ string) bool {
	for _, t := range eventTypes(bs) {
		if t == typ {
			return true
		}
	}
	return false
}

func countChannel(all []emitted, channel string) int {
	n := 0
	for _, e := range all {
		if e.channel == channel {
			n++
		}
	}
	return n
}

// fakePrelude is shared by every fake engine: it parses the engine argv and
// offers emit() and write_run_json() like runner/events.py.
const fakePrelude = `
import json, os, sys, time
argv = sys.argv[1:]
run_dir = argv[argv.index("-o") + 1]
ev_path = argv[argv.index("--events") + 1]

def pid_start():
    s = open("/proc/self/stat").read()
    return int(s.rsplit(")", 1)[1].split()[19])

def write_run_json():
    data = {"pid": os.getpid(), "pgid": os.getpgrp(), "pid_start": pid_start(),
            "target": argv[0], "flags": {}, "started": int(time.time() * 1000)}
    open(os.path.join(run_dir, "run.json"), "w").write(json.dumps(data))

_ev = open(ev_path, "a")

def emit(type, **kw):
    kw.update(v=1, t=int(time.time() * 1000), type=type)
    _ev.write(json.dumps(kw) + "\n")
    _ev.flush()

def start():
    write_run_json()
    emit("run_start", target=argv[0], flags={}, stages=["a"])
`

// fakeEngine writes an executable Python engine named bounty-run into a fresh
// temp dir and returns its path. body runs after fakePrelude.
func fakeEngine(t *testing.T, body string) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available for the fake engine")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bounty-run")
	src := "#!" + py + " -I\n" + fakePrelude + "\n" + strings.TrimSpace(body) + "\n"
	if err := os.WriteFile(path, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// newTestService returns a Service over a fresh outputs root using bin.
func newTestService(t *testing.T, bin string) (*Service, *recorder) {
	t.Helper()
	rec := newRecorder()
	s, err := New(Config{
		Root:             filepath.Join(t.TempDir(), "outputs"),
		EngineBin:        bin,
		Emitter:          rec,
		LivenessInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, rec
}

// killOnCleanup hard-kills the run in dir when the test ends.
func killOnCleanup(t *testing.T, s *Service, dir string) {
	t.Cleanup(func() { _ = s.HardKill(dir) })
}

// fakeClock is a manually advanced Clock.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	tickers []*fakeTicker
}

type fakeTicker struct {
	c       chan time.Time
	every   time.Duration
	next    time.Time
	stopped atomic.Bool
}

func (t *fakeTicker) C() <-chan time.Time { return t.c }
func (t *fakeTicker) Stop()               { t.stopped.Store(true) }

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTicker(d time.Duration) Ticker {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTicker{c: make(chan time.Time, 1), every: d, next: c.now.Add(d)}
	c.tickers = append(c.tickers, t)
	return t
}

// Advance moves time forward, firing (without blocking, like time.Ticker)
// every ticker that came due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.tickers {
		if t.stopped.Load() {
			continue
		}
		for !t.next.After(c.now) {
			select {
			case t.c <- c.now:
			default:
			}
			t.next = t.next.Add(t.every)
		}
	}
}

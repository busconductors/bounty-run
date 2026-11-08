package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"bountyrun/tui/internal/runstore"
)

// fakeEngine writes a script that records its pid, appends run_start to the
// file after --events and sleeps (ruling R4: same behaviour as Task 11's fake).
func fakeEngine(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-engine.sh")
	body := `#!/bin/sh
ev=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--events" ]; then ev="$a"; fi
  prev="$a"
done
echo $$ > "$(dirname "$ev")/fake.pid"
echo '{"v":1,"t":1,"type":"run_start","target":"example.com","stages":["subs"]}' >> "$ev"
sleep 10
`
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func startLaunch(t *testing.T, cfg Config) *teatest.TestModel {
	t.Helper()
	tm := teatest.NewTestModel(t, NewRoot(cfg), teatest.WithInitialTermSize(120, 50))
	teatest.WaitFor(t, tm.Output(), contains("Runs"), teatest.WithDuration(5*time.Second))
	tm.Send(tea.KeyPressMsg{Code: 'n', Text: "n"})
	teatest.WaitFor(t, tm.Output(), contains("Target"), teatest.WithDuration(5*time.Second))
	return tm
}

// submitForm types target and presses enter through every field.
func submitForm(tm *teatest.TestModel, target string) {
	tm.Type(target)
	for range 5 {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	}
}

func finalRoot(t *testing.T, tm *teatest.TestModel) *Root {
	t.Helper()
	tm.Quit()
	return tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(*Root)
}

func TestLaunchBlockedAtCap(t *testing.T) {
	root := t.TempDir()
	ps, err := runstore.PIDStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	for i := range 3 {
		writeRun(t, root, "busy"+strconv.Itoa(i)+".example.com", "1", os.Getpid(), ps, now,
			`{"v":1,"t":1,"type":"run_start"}`)
	}
	tm := startLaunch(t, Config{OutputsRoot: root, EngineBin: fakeEngine(t)})
	submitForm(tm, "example.com")
	teatest.WaitFor(t, tm.Output(), contains("3 runs already active"), teatest.WithDuration(5*time.Second))
	r := finalRoot(t, tm)
	if r.Screen() != "launch" {
		t.Fatalf("screen = %s", r.Screen())
	}
	if _, err := os.Stat(filepath.Join(root, "example.com")); !os.IsNotExist(err) {
		t.Fatalf("a run dir was created: %v", err)
	}
}

func TestLaunchInvalidTarget(t *testing.T) {
	root := t.TempDir()
	tm := startLaunch(t, Config{OutputsRoot: root, EngineBin: fakeEngine(t)})
	submitForm(tm, "not a domain")
	teatest.WaitFor(t, tm.Output(), contains("not a valid domain"), teatest.WithDuration(5*time.Second))
	r := finalRoot(t, tm)
	if r.Screen() != "launch" {
		t.Fatalf("screen = %s", r.Screen())
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatalf("spawned anyway: %v", ents)
	}
}

func TestLaunchSpawnsAndAttaches(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { // kill the fake engine even if the test fails
		pids, _ := filepath.Glob(filepath.Join(root, "example.com", "*", "fake.pid"))
		for _, p := range pids {
			b, _ := os.ReadFile(p)
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		}
	})
	tm := startLaunch(t, Config{OutputsRoot: root, EngineBin: fakeEngine(t)})
	submitForm(tm, "HTTPS://Example.COM/path")
	teatest.WaitFor(t, tm.Output(), contains("example.com ─ running"), teatest.WithDuration(8*time.Second))
	r := finalRoot(t, tm)
	if r.Screen() != "monitor" || r.monitor == nil {
		t.Fatalf("screen = %s", r.Screen())
	}
	if filepath.Dir(r.monitor.dir) != filepath.Join(root, "example.com") {
		t.Fatalf("monitor dir = %s", r.monitor.dir)
	}
}

func TestLaunchNoStartShowsLogAndEscReturns(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(t.TempDir(), "bad.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf 'boom \\033[2Jhere\\n'\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	tm := startLaunch(t, Config{OutputsRoot: root, EngineBin: bin})
	submitForm(tm, "example.com")
	teatest.WaitFor(t, tm.Output(), contains("boom here"), teatest.WithDuration(8*time.Second))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	teatest.WaitFor(t, tm.Output(), contains("active"), teatest.WithDuration(5*time.Second))
	r := finalRoot(t, tm)
	if r.Screen() != "runs" {
		t.Fatalf("screen = %s", r.Screen())
	}
}

func TestLaunchNoStartStopsEngine(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(t.TempDir(), "silent.sh")
	// Never writes run_start; records its pid next to events.jsonl and hangs.
	body := `#!/bin/sh
ev=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--events" ]; then ev="$a"; fi
  prev="$a"
done
echo $$ > "$(dirname "$ev")/fake.pid"
echo "warming up forever"
sleep 30
`
	if err := os.WriteFile(bin, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	fakePID := func() int {
		pids, _ := filepath.Glob(filepath.Join(root, "example.com", "*", "fake.pid"))
		for _, p := range pids {
			b, _ := os.ReadFile(p)
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
				return pid
			}
		}
		return 0
	}
	t.Cleanup(func() { // kill the fake engine even if the test fails
		if pid := fakePID(); pid > 0 {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	})
	tm := startLaunch(t, Config{OutputsRoot: root, EngineBin: bin})
	submitForm(tm, "example.com")
	teatest.WaitFor(t, tm.Output(), contains("stopped"), teatest.WithDuration(8*time.Second))
	r := finalRoot(t, tm)
	v := plain(r.launch.View())
	for _, w := range []string{"engine did not start within 3s — stopped", "warming up forever"} {
		if !strings.Contains(v, w) {
			t.Fatalf("missing %q\n%s", w, v)
		}
	}
	pid := fakePID()
	if pid == 0 {
		t.Fatal("fake engine never ran")
	}
	deadline := time.Now().Add(2 * time.Second)
	for syscall.Kill(pid, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		t.Fatal("engine still running after the launch gave up")
	}
	if logs, _ := filepath.Glob(filepath.Join(root, "example.com", "*", "engine.log")); len(logs) != 1 {
		t.Fatalf("run dir not kept: %v", logs)
	}
}

func TestLaunchSpawnFailureRemovesDir(t *testing.T) {
	root := t.TempDir()
	tm := startLaunch(t, Config{OutputsRoot: root, EngineBin: filepath.Join(t.TempDir(), "missing")})
	submitForm(tm, "example.com")
	teatest.WaitFor(t, tm.Output(), contains("launch failed"), teatest.WithDuration(5*time.Second))
	finalRoot(t, tm)
	if ents, _ := os.ReadDir(filepath.Join(root, "example.com")); len(ents) != 0 {
		t.Fatalf("phantom run dir left: %v", ents)
	}
}

func TestLaunchEscReturnsToRuns(t *testing.T) {
	tm := startLaunch(t, Config{OutputsRoot: t.TempDir()})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	teatest.WaitFor(t, tm.Output(), contains("active"), teatest.WithDuration(5*time.Second))
	if r := finalRoot(t, tm); r.Screen() != "runs" {
		t.Fatalf("screen = %s", r.Screen())
	}
}

func TestLaunchOptionsFromForm(t *testing.T) {
	l := newLaunch(Config{})
	l.target, l.optins, l.skips, l.timeout, l.maxParam = " Example.com ", []string{"tls", "headi"}, []string{"vuln"}, "30", ""
	o, err := l.options()
	if err != nil {
		t.Fatal(err)
	}
	if o.Target != "example.com" || !o.TLS || !o.Headi || o.Nikto || o.Timeout != 30 || o.MaxParamURLs != 0 ||
		len(o.Skip) != 1 || o.Skip[0] != "vuln" {
		t.Fatalf("%+v", o)
	}
	for _, bad := range []string{"0", "-3", "x"} {
		if posInt(bad) == nil {
			t.Errorf("posInt(%q) accepted", bad)
		}
	}
	if posInt("") != nil || posInt("12") != nil {
		t.Error("posInt rejected valid input")
	}
}

// TestStageIDsMatchEngine guards against drift between the launch form's
// skip list and runner/cli.py STAGE_IDS.
func TestStageIDsMatchEngine(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "bounty_run.py")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("bounty_run.py not found walking up from cwd")
		}
		root = parent
	}
	cmd := exec.Command(py, "-c", "import json; from runner.cli import STAGE_IDS; print(json.dumps(STAGE_IDS))")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python3: %v", err)
	}
	var want []string
	if err := json.Unmarshal(out, &want); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if !slices.Equal(stageIDs, want) {
		t.Fatalf("stageIDs = %v\nrunner/cli.py STAGE_IDS = %v", stageIDs, want)
	}
}

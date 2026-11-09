package ui

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"bountyrun/tui/internal/engine"
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
	if l.preset != "standard" {
		t.Fatalf("default preset = %q", l.preset)
	}
	l.target, l.timeout, l.maxParam = " Example.com ", "30", ""
	o, err := l.options()
	if err != nil {
		t.Fatal(err)
	}
	if o.Target != "example.com" || o.Timeout != 30 || o.MaxParamURLs != 0 {
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

func TestLaunchPresetOptions(t *testing.T) {
	cases := []struct {
		preset string
		custom []string
		skip   []string
		flags  engine.Options // only the bool flags are compared
	}{
		{"quick", nil, []string{"vuln", "content", "api", "param"}, engine.Options{}},
		{"standard", nil, []string{"param"}, engine.Options{Nmap: true}},
		{"deep", nil, nil, engine.Options{Amass: true, Nmap: true, NmapFull: true, TLS: true, Nikto: true, Metis: true, Headi: true}},
		{"custom", []string{"subs", "live", "nikto", "headi"}, []string{"panel", "cf", "origin", "origin_deep", "waf", "dork",
			"vuln", "content", "api", "param", "secret", "headers", "cors", "tech"}, engine.Options{Nikto: true, Headi: true}},
	}
	for _, c := range cases {
		l := newLaunch(Config{})
		l.target, l.preset = "a.com", c.preset
		if c.custom != nil {
			l.custom = c.custom
		}
		o, err := l.options()
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(o.Skip, c.skip) {
			t.Errorf("%s: skip = %v, want %v", c.preset, o.Skip, c.skip)
		}
		got := engine.Options{Amass: o.Amass, Nmap: o.Nmap, NmapFull: o.NmapFull, TLS: o.TLS, Nikto: o.Nikto, Metis: o.Metis, Headi: o.Headi}
		if !reflect.DeepEqual(got, c.flags) {
			t.Errorf("%s: flags = %+v, want %+v", c.preset, got, c.flags)
		}
	}
}

func TestLaunchCustomDefaultsToStandard(t *testing.T) {
	l := newLaunch(Config{})
	l.target, l.preset = "a.com", "custom"
	o, _ := l.options()
	l.preset = "standard"
	s, _ := l.options()
	if !reflect.DeepEqual(o, s) {
		t.Fatalf("custom %+v != standard %+v", o, s)
	}
}

// The default (Standard) preset's description is visible on the launch screen.
// Asserted against the rendered view, not the output stream: teatest's buffer
// is consuming and bubbletea diffs frames, so a frame startLaunch already read
// (the description renders on the blurred Preset field too) is not re-emitted.
func TestLaunchPresetDescriptionShown(t *testing.T) {
	tm := startLaunch(t, Config{OutputsRoot: t.TempDir()})
	r := finalRoot(t, tm)
	if v := plain(r.launch.View()); !strings.Contains(v, "Quick + nmap top-1000") {
		t.Fatalf("standard preset description not shown:\n%s", v)
	}
}

// Choosing the Custom preset reveals the stage list with its inline hints.
func TestLaunchCustomPageListsHints(t *testing.T) {
	tm := startLaunch(t, Config{OutputsRoot: t.TempDir()})
	// huh moves focus asynchronously (nextFieldMsg), so a key sent immediately
	// after the previous one can be processed before focus settles. Pace the
	// navigation so each keypress lands on the field it is meant for.
	key := func(c rune) {
		tm.Send(tea.KeyPressMsg{Code: c})
		time.Sleep(150 * time.Millisecond)
	}
	tm.Type("example.com")
	time.Sleep(150 * time.Millisecond)
	key(tea.KeyEnter) // target → preset (standard)
	key(tea.KeyDown)  // standard → deep
	key(tea.KeyDown)  // deep → custom
	key(tea.KeyEnter) // preset → timeout
	key(tea.KeyEnter) // timeout → max param
	key(tea.KeyEnter) // max param → custom page (group 2 appears)
	// The Custom stages group has never rendered before, so this whole frame is
	// fresh output — reliable to match even against teatest's diffed stream.
	teatest.WaitFor(t, tm.Output(), contains("Custom stages"), teatest.WithDuration(5*time.Second))
	r := finalRoot(t, tm)
	if r.Screen() != "launch" || r.launch.state != launchEditing {
		t.Fatalf("screen = %s state = %d", r.Screen(), r.launch.state)
	}
	v := plain(r.launch.View())
	for _, w := range []string{"Custom stages", "subdomain enum"} {
		if !strings.Contains(v, w) {
			t.Fatalf("missing %q in custom page:\n%s", w, v)
		}
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
	// Every preset's argv must parse and plan exactly the intended stages.
	planned := map[string][]string{
		"quick":    {"subs", "panel", "live", "cf", "origin", "waf", "dork", "secret", "headers", "cors", "tech"},
		"standard": {"subs", "panel", "live", "cf", "origin", "nmap", "waf", "dork", "vuln", "content", "api", "secret", "headers", "cors", "tech"},
		"deep":     stageIDs,
	}
	const script = `import json, sys
from runner.cli import build_parser, PLANNED_STAGES, STAGE_IDS
a = build_parser().parse_args(json.loads(sys.argv[1]))
skip = set(x for x in (a.skip or "").split(",") if x)
bad = skip - set(STAGE_IDS) - {"origin_deep"}
print(json.dumps({"planned": PLANNED_STAGES(a, skip), "bad": sorted(bad), "amass": a.amass, "full": a.nmap_full}))`
	for id, wantStages := range planned {
		l := newLaunch(Config{})
		l.target, l.preset = "a.com", id
		o, err := l.options()
		if err != nil {
			t.Fatal(err)
		}
		argv, _ := json.Marshal(engine.Argv(o, "/tmp/x"))
		cmd := exec.Command(py, "-c", script, string(argv))
		cmd.Dir = root
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: python3: %v", id, err)
		}
		var got struct {
			Planned, Bad []string
			Amass, Full  bool
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("decode %q: %v", out, err)
		}
		if len(got.Bad) > 0 || !slices.Equal(got.Planned, wantStages) {
			t.Errorf("%s: planned %v (bad skip tokens %v), want %v", id, got.Planned, got.Bad, wantStages)
		}
		if deep := id == "deep"; got.Amass != deep || got.Full != deep {
			t.Errorf("%s: amass=%v nmap-full=%v", id, got.Amass, got.Full)
		}
	}
}

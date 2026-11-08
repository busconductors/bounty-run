package ui

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"bountyrun/tui/internal/runstore"
)

func writeRun(t *testing.T, root, target, ts string, pid int, pidStart, started int64, lines ...string) string {
	t.Helper()
	d := filepath.Join(root, target, ts)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	rj := fmt.Sprintf(`{"pid":%d,"pgid":%d,"pid_start":%d,"target":%q,"flags":{},"started":%d}`,
		pid, pid, pidStart, target, started)
	os.WriteFile(filepath.Join(d, "run.json"), []byte(rj), 0o644)
	os.WriteFile(filepath.Join(d, "events.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	return d
}

// fixtureRoot builds a root with one running, one ok, one crashed and one
// unknown-status run. The running run is newest-first by Discover ordering.
func fixtureRoot(t *testing.T) (root, liveDir string) {
	t.Helper()
	root = t.TempDir()
	ps, err := runstore.PIDStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	liveDir = writeRun(t, root, "live.example.com", "3", os.Getpid(), ps, now-3600_000,
		`{"v":1,"t":1,"type":"run_start"}`,
		`{"v":1,"t":2,"type":"stage_start","stage":"nuclei"}`,
		`{"v":1,"t":3,"type":"finding","severity":"high"}`)
	writeRun(t, root, "done.example.com", "2", 999999999, 1, now-7200_000,
		fmt.Sprintf(`{"v":1,"t":%d,"type":"run_end","status":"ok","totals":{"critical":1,"low":4}}`, now-3600_000))
	writeRun(t, root, "dead.example.com", "1", 999999999, 1, now-9000_000,
		`{"v":1,"t":1,"type":"run_start"}`)
	writeRun(t, root, "weird.example.com", "0", 999999999, 1, now-9500_000,
		fmt.Sprintf(`{"v":1,"t":%d,"type":"run_end","status":"exploded","totals":{}}`, now-9400_000))
	return
}

func contains(s string) func([]byte) bool {
	return func(b []byte) bool { return bytes.Contains(b, []byte(s)) }
}

func TestRunsRendersRows(t *testing.T) {
	root, _ := fixtureRoot(t)
	tm := teatest.NewTestModel(t, NewRoot(Config{OutputsRoot: root}))
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		for _, w := range []string{"live.example.com", "done.example.com", "dead.example.com",
			"weird.example.com", "running", "crashed", "exploded", "1/3 active", "nuclei"} {
			if !bytes.Contains(b, []byte(w)) {
				return false
			}
		}
		return true
	}, teatest.WithDuration(5*time.Second))
	tm.Quit()
}

func TestRunsEnterAttaches(t *testing.T) {
	root, live := fixtureRoot(t)
	tm := teatest.NewTestModel(t, NewRoot(Config{OutputsRoot: root}))
	teatest.WaitFor(t, tm.Output(), contains("live.example.com"), teatest.WithDuration(5*time.Second))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	teatest.WaitFor(t, tm.Output(), contains("monitor:"), teatest.WithDuration(5*time.Second))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	teatest.WaitFor(t, tm.Output(), contains("1/3 active"), teatest.WithDuration(5*time.Second))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	teatest.WaitFor(t, tm.Output(), contains("monitor:"), teatest.WithDuration(5*time.Second))
	tm.Quit()
	r := tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(*Root)
	if r.Screen() != "monitor" || r.monitor.dir != live {
		t.Fatalf("screen %q dir %v", r.Screen(), r.monitor)
	}
}

func TestFmtElapsed(t *testing.T) {
	if got := fmtElapsed(72*time.Minute + 5*time.Second); got != "1h12m" {
		t.Fatal(got)
	}
	if got := fmtElapsed(3 * time.Minute); got != "0h03m" {
		t.Fatal(got)
	}
}

func TestUnknownStatusGlyph(t *testing.T) {
	if g, _ := glyph(runstore.Status("exploded")); g != "?" {
		t.Fatal(g)
	}
}

func plain(s string) string { return ansi.Strip(s) }

func mkRuns(dirs ...string) []runstore.Run {
	var rs []runstore.Run
	for _, d := range dirs {
		rs = append(rs, runstore.Run{Info: runstore.RunInfo{Dir: d, Target: d}, Status: runstore.OK, Sev: map[string]int{}})
	}
	return rs
}

func TestRowAlignmentSelectedVsNot(t *testing.T) {
	m := newRunsModel("x")
	r := runstore.Run{Info: runstore.RunInfo{Target: "a.com"}, Status: runstore.Crashed,
		Sev: map[string]int{"high": 2}, Elapsed: 72 * time.Minute}
	sel, un := plain(m.row(r, true)), plain(m.row(r, false))
	if strings.Index(sel, "crashed") != strings.Index(un, "crashed") || strings.Index(sel, "H2") != strings.Index(un, "H2") {
		t.Fatalf("misaligned:\n%q\n%q", sel, un)
	}
	if sel != un {
		t.Fatalf("plain text differs:\n%q\n%q", sel, un)
	}
}

func TestDiscoverErrorKeepsList(t *testing.T) {
	m := newRunsModel("x")
	m.Update(runsMsg{runs: mkRuns("a", "b")})
	m.Update(runsMsg{err: errors.New("boom")})
	v := plain(m.View())
	if !strings.Contains(v, "error: boom") || !strings.Contains(v, "a ") || !strings.Contains(v, "b ") {
		t.Fatal(v)
	}
	m.root = "[" // invalid glob pattern -> real Discover error
	msg := m.load()().(runsMsg)
	if msg.err == nil {
		t.Fatal("expected error")
	}
	m.Update(msg)
	m.Update(runsMsg{runs: mkRuns("a", "b")})
	if strings.Contains(plain(m.View()), "error:") {
		t.Fatal("error should clear on success")
	}
}

func TestSelectionFollowsDir(t *testing.T) {
	m := newRunsModel("x")
	m.Update(runsMsg{runs: mkRuns("a", "b", "c")})
	m.Update(tea.KeyPressMsg{Code: tea.KeyDown}) // b
	m.Update(runsMsg{runs: mkRuns("new", "a", "b", "c")})
	if m.cursor != 2 {
		t.Fatalf("cursor %d", m.cursor)
	}
	cmd := m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if got := cmd().(AttachMsg).Dir; got != "b" {
		t.Fatal(got)
	}
	// selected run vanishes: clamp
	m.Update(runsMsg{runs: mkRuns("a")})
	if m.cursor != 0 || m.selDir != "a" {
		t.Fatalf("cursor %d sel %q", m.cursor, m.selDir)
	}
}

func TestRenderedDetails(t *testing.T) {
	root, _ := fixtureRoot(t)
	m := newRunsModel(root)
	m.Update(m.load()())
	v := plain(m.View())
	for _, w := range []string{"C1", "L4", "H1", "—"} {
		if !strings.Contains(v, w) {
			t.Errorf("missing %q in\n%s", w, v)
		}
	}
	if !regexp.MustCompile(`\dh\d\dm`).MatchString(v) {
		t.Errorf("no XhYYm in\n%s", v)
	}
	lines := strings.Split(v, "\n")
	var rows []string
	for _, l := range lines {
		for _, g := range []string{"●", "✓", "✗", "?"} {
			if strings.HasPrefix(l, g+" ") {
				rows = append(rows, l)
			}
		}
	}
	if len(rows) != 4 || !strings.HasPrefix(rows[0], "●") {
		t.Fatalf("rows %q", rows)
	}
	found := false
	for _, l := range rows {
		if strings.HasPrefix(l, "? ") && strings.Contains(l, "weird") && strings.Contains(l, "exploded") {
			found = true
		}
	}
	if !found {
		t.Fatalf("unknown row missing: %q", rows)
	}
}

func TestNewRunAppearsAfterTick(t *testing.T) {
	root, _ := fixtureRoot(t)
	tm := teatest.NewTestModel(t, NewRoot(Config{OutputsRoot: root}))
	teatest.WaitFor(t, tm.Output(), contains("live.example.com"), teatest.WithDuration(5*time.Second))
	writeRun(t, root, "late.example.com", "9", 999999999, 1, time.Now().UnixMilli(),
		`{"v":1,"t":1,"type":"run_start"}`)
	teatest.WaitFor(t, tm.Output(), contains("late.example.com"), teatest.WithDuration(5*time.Second))
	tm.Quit()
}

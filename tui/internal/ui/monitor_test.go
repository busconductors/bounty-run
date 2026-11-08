package ui

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"bountyrun/tui/internal/events"
	"bountyrun/tui/internal/runstore"
)

// monHarness runs a MonitorModel standalone under teatest and records detach.
type monHarness struct {
	m        *MonitorModel
	detached bool
}

func (h *monHarness) Init() tea.Cmd { return h.m.Init() }

func (h *monHarness) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if _, ok := msg.(ShowRunsMsg); ok {
		h.detached = true
		return h, tea.Quit
	}
	_, cmd := h.m.Update(msg)
	return h, cmd
}

func (h *monHarness) View() tea.View { return h.m.View() }

// runDirFrom copies a testdata fixture to <tmp>/events.jsonl.
func runDirFrom(t *testing.T, fixture string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "events.jsonl"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func startMonitor(t *testing.T, dir string) (*teatest.TestModel, *monHarness) {
	t.Helper()
	mm := NewMonitor(dir, Config{})
	h := &monHarness{m: &mm}
	tm := teatest.NewTestModel(t, h, teatest.WithInitialTermSize(120, 40))
	return tm, h
}

// finishedMonitor attaches to the full fixture and waits until run_end is shown.
func finishedMonitor(t *testing.T) (*teatest.TestModel, *monHarness) {
	t.Helper()
	tm, h := startMonitor(t, runDirFrom(t, "full_run.jsonl"))
	teatest.WaitFor(t, tm.Output(), contains("finished"), teatest.WithDuration(5*time.Second))
	return tm, h
}

func finalView(t *testing.T, tm *teatest.TestModel) string {
	t.Helper()
	tm.Quit()
	h := tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(*monHarness)
	return plain(h.m.render())
}

func TestMonitorTimelineFromEvents(t *testing.T) {
	tm, _ := finishedMonitor(t)
	v := finalView(t, tm)
	for _, s := range []string{"✓ subs", "✓ live", "✓ vuln"} {
		if !strings.Contains(v, s) {
			t.Errorf("missing %q in\n%s", s, v)
		}
	}
	if !strings.Contains(v, "nuclei line 20") || !strings.Contains(v, "acme.com") {
		t.Errorf("output/header missing in\n%s", v)
	}
}

func findingRows(v string) []string {
	var rows []string
	for _, l := range strings.Split(v, "\n") {
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if strings.Contains(l, sev+" ") && strings.Contains(l, "acme.com") {
				rows = append(rows, l)
			}
		}
	}
	return rows
}

func TestMonitorFindingsSorted(t *testing.T) {
	tm, _ := finishedMonitor(t)
	v := finalView(t, tm)
	rows := findingRows(v)
	if len(rows) != 4 {
		t.Fatalf("rows %q\n%s", rows, v)
	}
	want := []string{"exposed-git", "cors-misconfig", "weak-cipher", "tech-detect"}
	for i, w := range want {
		if !strings.Contains(rows[i], w) {
			t.Fatalf("row %d = %q, want %s", i, rows[i], w)
		}
	}
}

func TestMonitorFilter(t *testing.T) {
	tm, _ := finishedMonitor(t)
	tm.Send(tea.KeyPressMsg{Code: 'f', Text: "f"})
	tm.Send(tea.KeyPressMsg{Code: 'f', Text: "f"})
	v := finalView(t, tm)
	rows := findingRows(v)
	if len(rows) != 1 || !strings.Contains(rows[0], "exposed-git") {
		t.Fatalf("rows %q\n%s", rows, v)
	}
	if !strings.Contains(v, "filter: high") {
		t.Fatalf("filter label missing\n%s", v)
	}
}

func TestMonitorDetailOverlay(t *testing.T) {
	tm, _ := finishedMonitor(t)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyTab})
	v := finalView(t, tm)
	for _, w := range []string{"https://dev.acme.com/.git/config", "Git repository exposed", "dev.acme.com"} {
		if !strings.Contains(v, w) {
			t.Fatalf("detail missing %q\n%s", w, v)
		}
	}
}

// Findings that arrive after an empty refresh must still be selectable.
func TestMonitorDetailAfterEmptyBatch(t *testing.T) {
	mm := NewMonitor("/runs/a", Config{})
	m := &mm
	m.update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.Msg{RunDir: "/runs/a",
		Ev: events.Event{Type: "run_start", Target: "a.com", Stages: []string{"vuln"}}}}})
	m.update(tea.KeyPressMsg{Code: 'f', Text: "f"}) // filter with no rows
	m.update(tea.KeyPressMsg{Code: 'f', Text: "f"})
	m.update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.Msg{RunDir: "/runs/a",
		Ev: events.Event{Type: "finding", Severity: "high", Template: "t1", Host: "h1", URL: "https://h1/x"}}}})
	m.update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if v := plain(m.render()); !m.detail || !strings.Contains(v, "https://h1/x") {
		t.Fatalf("detail=%v\n%s", m.detail, v)
	}
}

func TestRingCap(t *testing.T) {
	var r ring
	for i := 0; i <= 5000; i++ {
		r.Push(strconv.Itoa(i))
	}
	l := r.Lines()
	if len(l) != 5000 || l[0] != "1" || l[4999] != "5000" {
		t.Fatalf("len %d first %q last %q", len(l), l[0], l[len(l)-1])
	}
}

func TestMonitorDetachKeepsFile(t *testing.T) {
	dir := runDirFrom(t, "full_run.jsonl")
	path := filepath.Join(dir, "events.jsonl")
	before, _ := os.ReadFile(path)
	st0, _ := os.Stat(path)
	tm, _ := startMonitor(t, dir)
	teatest.WaitFor(t, tm.Output(), contains("finished"), teatest.WithDuration(5*time.Second))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEscape})
	h := tm.FinalModel(t, teatest.WithFinalTimeout(5*time.Second)).(*monHarness)
	if !h.detached {
		t.Fatal("esc did not send ShowRunsMsg")
	}
	if h.m.ctx.Err() == nil {
		t.Fatal("tail context not cancelled on detach")
	}
	select {
	case <-h.m.tailDone:
	case <-time.After(2 * time.Second):
		t.Fatal("tail goroutine did not exit")
	}
	after, _ := os.ReadFile(path)
	st1, _ := os.Stat(path)
	if !bytes.Equal(before, after) || !st0.ModTime().Equal(st1.ModTime()) {
		t.Fatal("fixture modified")
	}
	if _, err := os.Stat(filepath.Join(dir, "control")); err == nil {
		t.Fatal("detach must not write control")
	}
}

func TestMonitorQDetachesCtrlCQuits(t *testing.T) {
	mm := NewMonitor(t.TempDir(), Config{})
	m := &mm
	m.Init()
	cmd := m.update(tea.KeyPressMsg{Code: 'q', Text: "q"})
	if _, ok := cmd().(ShowRunsMsg); !ok || m.ctx.Err() == nil {
		t.Fatal("q should cancel and detach")
	}
	mm2 := NewMonitor(t.TempDir(), Config{})
	m2 := &mm2
	m2.Init()
	cmd = m2.update(tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl})
	if _, ok := cmd().(tea.QuitMsg); !ok || m2.ctx.Err() == nil {
		t.Fatal("ctrl+c should cancel and quit")
	}
}

func TestMonitorIncompatible(t *testing.T) {
	tm, _ := startMonitor(t, runDirFrom(t, "incompatible.jsonl"))
	teatest.WaitFor(t, tm.Output(), contains("incompatible engine version"), teatest.WithDuration(5*time.Second))
	tm.Quit()
}

func TestMonitorIgnoresOtherAttach(t *testing.T) {
	mm := NewMonitor("/runs/a", Config{})
	m := &mm
	m.Update(tailMsg{gen: m.gen + 1000, msgs: []tea.Msg{events.Msg{RunDir: "/runs/a",
		Ev: events.Event{Type: "output", Tool: "x", Line: "stale-gen"}}}})
	m.Update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.Msg{RunDir: "/runs/b",
		Ev: events.Event{Type: "output", Tool: "x", Line: "other-dir"}}}})
	m.Update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.Msg{RunDir: "/runs/a",
		Ev: events.Event{Type: "output", Tool: "x", Line: "mine"}}}})
	v := plain(m.render())
	if strings.Contains(v, "stale-gen") || strings.Contains(v, "other-dir") || !strings.Contains(v, "mine") {
		t.Fatal(v)
	}
}

func TestMonitorWarnShown(t *testing.T) {
	mm := NewMonitor("/runs/a", Config{})
	m := &mm
	m.Update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.WarnMsg{RunDir: "/runs/a", Text: "skipped malformed"}}})
	if v := plain(m.render()); !strings.Contains(v, "[warn] skipped malformed") {
		t.Fatal(v)
	}
}

const hostile = "a\x1b]0;pwned\x07b\x1b[2Jc\u009bd\x00e\x7ff\tg"

func TestSanitize(t *testing.T) {
	if got := sanitize(hostile); got != "abcdef\tg" {
		t.Fatalf("%q", got)
	}
}

func assertClean(t *testing.T, v string) {
	t.Helper()
	for _, bad := range []string{"\x1b]", "pwned", "\x07", "\x1b[2J", "\u009b", "\x00", "\x7f"} {
		if strings.Contains(v, bad) {
			t.Fatalf("rendered view contains %q:\n%q", bad, v)
		}
	}
}

func TestMonitorSanitizesEngineText(t *testing.T) {
	mm := NewMonitor("/runs/a", Config{})
	m := &mm
	send := func(ev events.Event) {
		m.Update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.Msg{RunDir: "/runs/a", Ev: ev}}})
	}
	send(events.Event{Type: "run_start", Target: hostile, Stages: []string{hostile}})
	send(events.Event{Type: "stage_end", Stage: hostile, Status: "skipped", Reason: hostile})
	send(events.Event{Type: "output", Tool: hostile, Line: hostile})
	send(events.Event{Type: "log", Level: "warn", Msg: hostile})
	send(events.Event{Type: "finding", Severity: "high", Template: hostile, Host: hostile, URL: hostile, Summary: hostile})
	m.Update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.WarnMsg{RunDir: "/runs/a", Text: hostile}}})
	send(events.Event{Type: "run_end", Status: hostile, Error: hostile})
	assertClean(t, m.render())
	m.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	if !m.detail {
		t.Fatal("detail not opened")
	}
	assertClean(t, m.render())
}

func TestRunsRowSanitized(t *testing.T) {
	m := newRunsModel("x")
	m.Update(runsMsg{runs: []runstore.Run{{Info: runstore.RunInfo{Dir: "d", Target: hostile},
		Status: runstore.Status(hostile), CurrentStage: hostile, Sev: map[string]int{}}}})
	assertClean(t, m.View())
}

func TestRootReattachCancelsPreviousTail(t *testing.T) {
	dir := runDirFrom(t, "full_run.jsonl")
	r := NewRoot(Config{OutputsRoot: t.TempDir()}).(*Root)
	r.Update(AttachMsg{Dir: dir})
	first := r.monitor
	r.Update(AttachMsg{Dir: dir})
	second := r.monitor
	if first == second || first.ctx.Err() == nil || second.ctx.Err() != nil || first.gen == second.gen {
		t.Fatal("re-attach must cancel the old tail and start a fresh model")
	}
	r.Update(ShowRunsMsg{})
	if second.ctx.Err() == nil || r.monitor != nil || r.Screen() != "runs" {
		t.Fatal("detach must cancel the tail")
	}
	for _, m := range []*MonitorModel{first, second} {
		select {
		case <-m.tailDone:
		case <-time.After(2 * time.Second):
			t.Fatal("tail goroutine still running")
		}
	}
}

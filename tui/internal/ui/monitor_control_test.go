package ui

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"bountyrun/tui/internal/events"
	"bountyrun/tui/internal/runstore"
)

// runningDir is a run with vuln currently running and no run_end.
func runningDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	lines := strings.Join([]string{
		`{"v":1,"t":1,"type":"run_start","target":"acme.com","stages":["subs","vuln"]}`,
		`{"v":1,"t":2,"type":"stage_start","stage":"subs"}`,
		`{"v":1,"t":3,"type":"stage_end","stage":"subs","status":"ok"}`,
		`{"v":1,"t":4,"type":"stage_start","stage":"vuln"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(d, "events.jsonl"), []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func startControlMonitor(t *testing.T, dir string, timeout time.Duration) *teatest.TestModel {
	t.Helper()
	mm := NewMonitor(dir, Config{})
	if timeout > 0 {
		mm.controlTimeout = timeout
	}
	tm := teatest.NewTestModel(t, &monHarness{m: &mm}, teatest.WithInitialTermSize(120, 40))
	teatest.WaitFor(t, tm.Output(), contains("▶ vuln"), teatest.WithDuration(5*time.Second))
	return tm
}

func key(c rune) tea.KeyPressMsg { return tea.KeyPressMsg{Code: c, Text: string(c)} }

func waitFile(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		b, _ := os.ReadFile(path)
		if string(b) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %q, want %q", path, b, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestMonitorSkipWritesControl(t *testing.T) {
	dir := runningDir(t)
	tm := startControlMonitor(t, dir, 0)
	tm.Send(key('s'))
	teatest.WaitFor(t, tm.Output(), contains("skip vuln? y/n"), teatest.WithDuration(5*time.Second))
	tm.Send(key('y'))
	waitFile(t, filepath.Join(dir, "control"), "skip vuln\n")
	tm.Quit()
}

func TestMonitorConfirmDeclined(t *testing.T) {
	dir := runningDir(t)
	tm := startControlMonitor(t, dir, 0)
	tm.Send(key('c'))
	teatest.WaitFor(t, tm.Output(), contains("cancel run? y/n"), teatest.WithDuration(5*time.Second))
	tm.Send(key('n'))
	v := finalView(t, tm)
	if strings.Contains(v, "y/n") {
		t.Fatalf("prompt still shown\n%s", v)
	}
	if _, err := os.Stat(filepath.Join(dir, "control")); err == nil {
		t.Fatal("declined confirm wrote control")
	}
}

func TestMonitorHardKillOfferedAfterTimeout(t *testing.T) {
	dir := runningDir(t)
	tm := startControlMonitor(t, dir, 50*time.Millisecond)
	tm.Send(key('c'))
	teatest.WaitFor(t, tm.Output(), contains("cancel run? y/n"), teatest.WithDuration(5*time.Second))
	tm.Send(key('y'))
	teatest.WaitFor(t, tm.Output(), contains("K to hard kill"), teatest.WithDuration(5*time.Second))
	waitFile(t, filepath.Join(dir, "control"), "cancel\n")
	tm.Quit()
}

func TestMonitorHardKillKillsEngine(t *testing.T) {
	dir := runningDir(t)
	c := exec.Command("sleep", "60")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Process.Pid
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL) })
	waited := make(chan struct{})
	go func() { _ = c.Wait(); close(waited) }()
	ps, err := runstore.PIDStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	rj := fmt.Sprintf(`{"pid":%d,"pgid":%d,"pid_start":%d,"target":"acme.com","flags":{},"started":1}`, pid, pid, ps)
	os.WriteFile(filepath.Join(dir, "run.json"), []byte(rj), 0o644)

	tm := startControlMonitor(t, dir, 50*time.Millisecond)
	tm.Send(key('K')) // no banner yet: ignored
	select {
	case <-waited:
		t.Fatal("K killed without the banner")
	case <-time.After(300 * time.Millisecond):
	}
	tm.Send(key('c'))
	tm.Send(key('y'))
	teatest.WaitFor(t, tm.Output(), contains("K to hard kill"), teatest.WithDuration(5*time.Second))
	tm.Send(key('K'))
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatal("engine not killed")
	}
	tm.Quit()
}

func TestMonitorAckClearsPending(t *testing.T) {
	mm := NewMonitor("/runs/a", Config{})
	m := &mm
	send := func(ev events.Event) {
		m.update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.Msg{RunDir: "/runs/a", Ev: ev}}})
	}
	send(events.Event{Type: "run_start", Target: "a.com", Stages: []string{"vuln", "cors"}})
	send(events.Event{Type: "stage_start", Stage: "vuln"})
	m.update(key('s'))
	if cmd := m.update(key('y')); cmd == nil || m.pending == nil {
		t.Fatal("no control command / pending ack")
	}
	seq := m.pending.seq
	send(events.Event{Type: "stage_end", Stage: "cors", Status: "ok"}) // not the skipped stage
	if m.pending == nil {
		t.Fatal("unrelated stage_end cleared pending")
	}
	send(events.Event{Type: "stage_end", Stage: "vuln", Status: "skipped"})
	if m.pending != nil {
		t.Fatal("matching stage_end did not clear pending")
	}
	m.update(ackTimeoutMsg{gen: m.gen, seq: seq})
	if strings.Contains(plain(m.render()), "K to hard kill") {
		t.Fatal("banner shown after ack")
	}
	send(events.Event{Type: "stage_start", Stage: "cors"})
	m.update(key('s'))
	send(events.Event{Type: "stage_end", Stage: "cors", Status: "ok"})
	if m.confirm != "" {
		t.Fatal("skip prompt kept after its stage ended")
	}
}

func TestMonitorNoControlWhenEnded(t *testing.T) {
	dir := runDirFrom(t, "full_run.jsonl")
	tm, _ := startMonitor(t, dir)
	teatest.WaitFor(t, tm.Output(), contains("finished"), teatest.WithDuration(5*time.Second))
	tm.Send(key('s'))
	tm.Send(key('y'))
	tm.Send(key('c'))
	tm.Send(key('y'))
	v := finalView(t, tm)
	if strings.Contains(v, "y/n") {
		t.Fatalf("prompt shown on ended run\n%s", v)
	}
	if _, err := os.Stat(filepath.Join(dir, "control")); err == nil {
		t.Fatal("control written on ended run")
	}
}

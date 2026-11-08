package ui

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
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

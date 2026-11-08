package events

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "bounty_run.py")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("bounty_run.py not found walking up from cwd")
		}
		dir = parent
	}
}

// TestContractPythonEmitter runs the real Python emitter and decodes every line.
func TestContractPythonEmitter(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "events.jsonl")
	cmd := exec.Command(py, filepath.Join(root, "tests", "fixtures", "fake_run.py"), out)
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fake_run.py: %v\n%s", err, b)
	}

	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)

	seen := map[string]bool{}
	var evs []Event
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			e, derr := Decode(line)
			if derr != nil {
				t.Fatalf("decode %.120q: %v", line, derr)
			}
			seen[e.Type] = true
			evs = append(evs, e)
		}
		if err != nil {
			break
		}
	}
	want := []string{"run_start", "stage_start", "stage_end", "progress", "log", "output", "finding", "run_end"}
	for _, ty := range want {
		if !seen[ty] {
			t.Errorf("type %q not seen", ty)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("seen types = %v, want exactly %v", seen, want)
	}

	var gotBig, gotFinding, gotEnd bool
	for _, e := range evs {
		switch e.Type {
		case "output":
			if len(e.Line) == 100*1024 {
				gotBig = e.Line == strings.Repeat("x", 100*1024) && e.Stage == "nuclei" && e.Tool == "nuclei" && e.Stream == "stdout"
			}
		case "finding":
			gotFinding = e.Summary == "Exposed admin panel" && e.Severity == "high" &&
				e.Template == "admin-panel" && e.Host == "a.example.com" && e.URL == "https://a.example.com/admin"
		case "run_end":
			gotEnd = e.SummaryPath == "/tmp/run/summary.md" && e.Report == "/tmp/run/report.md" &&
				e.Status == "ok" && e.Totals["findings"] == 1 && e.Totals["hosts"] == 3 && e.Summary == ""
		}
	}
	if !gotBig {
		t.Error("100 KiB output line did not round-trip")
	}
	if !gotFinding {
		t.Error("finding fields did not round-trip")
	}
	if !gotEnd {
		t.Error("run_end fields did not round-trip")
	}
}

package engine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"bountyrun/tui/internal/runstore"
)

func TestNormalizeTarget(t *testing.T) {
	ok := map[string]string{
		"Example.COM":          "example.com",
		"  a.com  ":            "a.com",
		"https://a.com/x?y":    "a.com",
		"HTTP://A.com":         "a.com",
		"a.com.":               "a.com",
		"a.com:8443":           "a.com",
		"https://a.com:8443/p": "a.com",
		"sub.a-b.example.org":  "sub.a-b.example.org",
		"1.2.3.4:80":           "1.2.3.4", // IPs match the Python regex too
	}
	for in, want := range ok {
		got, err := NormalizeTarget(in)
		if err != nil || got != want {
			t.Errorf("NormalizeTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", "not a domain", "localhost", "-a.com", "a-.com", "a..com", "https://", "a_b.com", "user@a.com"} {
		if got, err := NormalizeTarget(in); err == nil {
			t.Errorf("NormalizeTarget(%q) = %q; want error", in, got)
		}
	}
}

func TestNewRunDirUnique(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 11, 8, 12, 30, 45, 0, time.UTC)
	d1, err := NewRunDir(root, "a.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != filepath.Join(root, "a.com", "20261108-123045") {
		t.Errorf("d1 = %s", d1)
	}
	d2, err := NewRunDir(root, "a.com", now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(d2, "-2") || d2 == d1 {
		t.Errorf("d2 = %s", d2)
	}
	d3, _ := NewRunDir(root, "a.com", now)
	if !strings.HasSuffix(d3, "-3") {
		t.Errorf("d3 = %s", d3)
	}
}

func TestArgv(t *testing.T) {
	a := Argv(Options{Target: "a.com", TLS: true, Skip: []string{"dork", "param"}}, "/r/d")
	if a[0] != "a.com" {
		t.Errorf("a[0] = %s", a[0])
	}
	for _, p := range [][]string{{"-o", "/r/d"}, {"--events", "/r/d/events.jsonl"}, {"--skip", "dork,param"}} {
		i := slices.Index(a, p[0])
		if i < 0 || i+1 >= len(a) || a[i+1] != p[1] {
			t.Errorf("missing %v in %v", p, a)
		}
	}
	for _, f := range []string{"--tls", "--no-banner"} {
		if !slices.Contains(a, f) {
			t.Errorf("missing %s", f)
		}
	}
	for _, f := range []string{"--timeout", "--max-param-urls", "--amass"} {
		if slices.Contains(a, f) {
			t.Errorf("unexpected %s in %v", f, a)
		}
	}
	b := Argv(Options{Target: "a.com", Timeout: 30, MaxParamURLs: 5, Amass: true, Nikto: true, Nmap: true, Metis: true, Headi: true}, "/d")
	for _, f := range []string{"--timeout", "--max-param-urls", "--amass", "--nikto", "--nmap", "--metis", "--headi"} {
		if !slices.Contains(b, f) {
			t.Errorf("missing %s in %v", f, b)
		}
	}
}

func killOnCleanup(t *testing.T, pid int) {
	t.Cleanup(func() { _ = syscall.Kill(-pid, syscall.SIGKILL); _ = syscall.Kill(pid, syscall.SIGKILL) })
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-engine.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// Fake engine finds the events path as the arg following --events (ruling R3).
const findEvents = `ev=""
prev=""
for a in "$@"; do
  if [ "$prev" = "--events" ]; then ev="$a"; fi
  prev="$a"
done
`

func sessionID(t *testing.T, pid int) int {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	n, _ := strconv.Atoi(f[3]) // field 6 = session
	return n
}

func TestSpawnDetachedAndWaitStarted(t *testing.T) {
	dir := t.TempDir()
	bin := writeScript(t, findEvents+`echo '{"v":1,"t":1,"type":"run_start","target":"a.com"}' >> "$ev"
sleep 5
`)
	pid, err := Spawn(bin, Argv(Options{Target: "a.com"}, dir), dir)
	if err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, pid)
	if err := WaitStarted(dir, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	if sid, mine := sessionID(t, pid), sessionID(t, os.Getpid()); sid == mine || sid != pid {
		t.Errorf("session id = %d, test = %d, pid = %d", sid, mine, pid)
	}
}

func TestWaitStartedTimeoutShowsLog(t *testing.T) {
	dir := t.TempDir()
	bin := writeScript(t, "echo boom\nexit 1\n")
	pid, err := Spawn(bin, Argv(Options{Target: "a.com"}, dir), dir)
	if err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, pid)
	err = WaitStarted(dir, 500*time.Millisecond)
	if !errors.Is(err, ErrNoStart) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("message lacks log: %v", err)
	}
}

func TestControlAtomic(t *testing.T) {
	dir := t.TempDir()
	if err := Skip(dir, "vuln"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "control"))
	if string(b) != "skip vuln\n" {
		t.Errorf("control = %q", b)
	}
	if err := Cancel(dir); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "control"))
	if string(b) != "cancel\n" {
		t.Errorf("control = %q", b)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("leftover temp files: %v", ents)
	}
}

func startGroup(t *testing.T) int {
	t.Helper()
	c := exec.Command("sleep", "60")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	pid := c.Process.Pid
	killOnCleanup(t, pid)
	go func() { _ = c.Wait() }()
	return pid
}

func TestHardKillKillsRecordedPgids(t *testing.T) {
	dir := t.TempDir()
	a, b := startGroup(t), startGroup(t)
	if err := os.WriteFile(filepath.Join(dir, "pids"), []byte(strconv.Itoa(b)+"\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := HardKill(runstore.RunInfo{PGID: a}, dir); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for _, g := range []int{a, b} {
		for syscall.Kill(-g, 0) == nil && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if syscall.Kill(-g, 0) == nil {
			t.Errorf("pgid %d still alive", g)
		}
	}
	// Already-dead groups are not an error; pgid <= 1 is never signalled.
	if err := HardKill(runstore.RunInfo{PGID: a}, dir); err != nil {
		t.Errorf("second kill: %v", err)
	}
	if err := HardKill(runstore.RunInfo{PGID: 1}, t.TempDir()); err != nil {
		t.Errorf("pgid 1: %v", err)
	}
}

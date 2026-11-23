package engine

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"bountyrun/core/runstore"
)

const runStartLine = `echo '{"v":1,"t":1,"type":"run_start","target":"a.com"}' >> "$ev"` + "\n"

// spawnFake starts body as a fake engine through the production spawn path and
// returns its RunInfo.
func spawnFake(t *testing.T, body string) runstore.RunInfo {
	t.Helper()
	dir := t.TempDir()
	bin := writeScript(t, findEvents+body)
	pid, err := Spawn(bin, Argv(Options{Target: "a.com"}, dir), dir)
	if err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, pid)
	start, _ := runstore.PIDStart(pid) // may already be gone: then 0
	return runstore.RunInfo{Dir: dir, PID: pid, PGID: pid, PIDStart: start}
}

func TestWaitLaunchSlowPreflightSucceeds(t *testing.T) {
	info := spawnFake(t, "sleep 4\n"+runStartLine+"sleep 30\n")
	if err := WaitLaunch(info, 20*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestWaitLaunchExitReturnsImmediately(t *testing.T) {
	info := spawnFake(t, "echo preflight-failed >&2\nexit 2\n")
	begin := time.Now()
	err := WaitLaunch(info, 20*time.Second)
	if !errors.Is(err, ErrExited) {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, ErrNoStart) {
		t.Errorf("exit must not look like a timeout: %v", err)
	}
	if d := time.Since(begin); d > time.Second {
		t.Errorf("took %s", d)
	}
	if !strings.Contains(err.Error(), "preflight-failed") {
		t.Errorf("message lacks stderr: %v", err)
	}
}

func TestWaitLaunchExitAfterRunStartIsSuccess(t *testing.T) {
	info := spawnFake(t, runStartLine+"exit 0\n")
	if err := WaitLaunch(info, 20*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestWaitLaunchDeadline(t *testing.T) {
	info := spawnFake(t, "sleep 30\n")
	err := WaitLaunch(info, 500*time.Millisecond)
	if !errors.Is(err, ErrNoStart) {
		t.Fatalf("err = %v", err)
	}
	if errors.Is(err, ErrExited) {
		t.Errorf("deadline must not look like an exit: %v", err)
	}
}

// An exited child that nobody has reaped is a zombie: /proc/<pid>/stat still
// exists with the same start time. It must still count as exited.
func TestWaitLaunchZombieCountsAsExited(t *testing.T) {
	dir := t.TempDir()
	c := exec.Command("sh", "-c", "echo zombie-out >&2; exit 3")
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Wait() })
	pid := c.Process.Pid
	start, err := runstore.PIDStart(pid)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !procGone(pid, start) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := runstore.PIDStart(pid); err != nil {
		t.Fatalf("child was reaped, not a zombie: %v", err)
	}
	info := runstore.RunInfo{Dir: dir, PID: pid, PGID: pid, PIDStart: start}
	begin := time.Now()
	if err := WaitLaunch(info, 20*time.Second); !errors.Is(err, ErrExited) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(begin); d > time.Second {
		t.Errorf("took %s", d)
	}
}

func TestLaunchTimeout(t *testing.T) {
	if got := LaunchTimeout(Options{}); got != 3*time.Second {
		t.Errorf("no proxy = %s", got)
	}
	if got := LaunchTimeout(Options{Proxy: "http://127.0.0.1:8080"}); got != 20*time.Second {
		t.Errorf("proxy = %s", got)
	}
}

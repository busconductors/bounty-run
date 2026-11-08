// Package engine starts, controls and kills the Python bounty-run engine.
package engine

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"bountyrun/tui/internal/events"
	"bountyrun/tui/internal/runstore"
)

// ErrNoStart means the engine never emitted run_start in time.
var ErrNoStart = errors.New("engine did not start")

// Options are the user-selectable engine flags. Zero ints mean "engine default".
type Options struct {
	Target                                string
	Amass, TLS, Nikto, Nmap, Metis, Headi bool
	Skip                                  []string
	Timeout, MaxParamURLs                 int
}

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// NormalizeTarget ports runner/cli.py _normalize_target, returning an error
// where Python returns "".
func NormalizeTarget(s string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if _, after, ok := strings.Cut(t, "://"); ok {
		t = after
	}
	t, _, _ = strings.Cut(t, "/")
	t, _, _ = strings.Cut(t, ":")
	t = strings.TrimRight(t, ".")
	if !domainRE.MatchString(t) {
		return "", fmt.Errorf("invalid target %q: not a domain", s)
	}
	return t, nil
}

// NewRunDir creates root/target/YYYYMMDD-HHMMSS (suffix -2, -3, ... if taken).
// The leaf is made with os.Mkdir so a race fails loudly instead of sharing a dir.
func NewRunDir(root, target string, now time.Time) (string, error) {
	parent := filepath.Join(root, target)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	base := filepath.Join(parent, now.Format("20060102-150405"))
	for i := 1; ; i++ {
		d := base
		if i > 1 {
			d = base + "-" + strconv.Itoa(i)
		}
		err := os.Mkdir(d, 0o755)
		if err == nil {
			return d, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
}

// Argv builds the engine command line (without the binary).
func Argv(o Options, dir string) []string {
	a := []string{o.Target, "-o", dir, "--events", dir + "/events.jsonl", "--no-banner"}
	for _, f := range []struct {
		on   bool
		flag string
	}{{o.Amass, "--amass"}, {o.TLS, "--tls"}, {o.Nikto, "--nikto"}, {o.Nmap, "--nmap"}, {o.Metis, "--metis"}, {o.Headi, "--headi"}} {
		if f.on {
			a = append(a, f.flag)
		}
	}
	if len(o.Skip) > 0 {
		a = append(a, "--skip", strings.Join(o.Skip, ","))
	}
	if o.Timeout > 0 {
		a = append(a, "--timeout", strconv.Itoa(o.Timeout))
	}
	if o.MaxParamURLs > 0 {
		a = append(a, "--max-param-urls", strconv.Itoa(o.MaxParamURLs))
	}
	return a
}

// Spawn starts the engine in its own session with stdout/stderr going to
// dir/engine.log and stdin from /dev/null. A goroutine Waits on the child so it
// never lingers as a zombie while the TUI keeps running.
func Spawn(bin string, argv []string, dir string) (int, error) {
	logf, err := os.OpenFile(filepath.Join(dir, "engine.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, err
	}
	defer logf.Close() // the child holds its own dup after Start
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return 0, err
	}
	defer devnull.Close()
	cmd := exec.Command(bin, argv...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	go func() { _ = cmd.Wait() }()
	return cmd.Process.Pid, nil
}

// WaitStarted polls dir/events.jsonl for a run_start event.
func WaitStarted(dir string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if hasRunStart(filepath.Join(dir, "events.jsonl")) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w within %s; engine.log tail:\n%s", ErrNoStart, timeout, logTail(filepath.Join(dir, "engine.log"), 20))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func hasRunStart(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		if ev, err := events.Decode(line); err == nil && ev.Type == "run_start" {
			return true
		}
	}
	return false
}

func logTail(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return "(no engine.log)"
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return strings.Join(lines, "\n")
}

// Skip asks the engine to skip a stage.
func Skip(dir, stage string) error { return writeControl(dir, "skip "+stage+"\n") }

// Cancel asks the engine to cancel the run.
func Cancel(dir string) error { return writeControl(dir, "cancel\n") }

// writeControl writes via temp file + rename so the engine never sees a partial line.
func writeControl(dir, line string) error {
	// Append semantics: keep any command the engine has not consumed yet.
	// (Missing file counts as empty.)
	old, err := os.ReadFile(filepath.Join(dir, "control"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	content := string(old) + line
	f, err := os.CreateTemp(dir, ".control-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.WriteString(content)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, "control")); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// HardKill SIGKILLs the engine's process group and every group listed in
// dir/pids (tools run in their own sessions). ESRCH is ignored; pgid <= 1 is
// never signalled.
func HardKill(info runstore.RunInfo, dir string) error {
	groups := []int{info.PGID}
	if b, err := os.ReadFile(filepath.Join(dir, "pids")); err == nil {
		for _, l := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(l); err == nil {
				groups = append(groups, n)
			}
		}
	}
	self := syscall.Getpgrp() // never kill the TUI's own group
	var errs []error
	for _, g := range groups {
		if g <= 1 || g == self {
			continue
		}
		if err := syscall.Kill(-g, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Errorf("kill pgid %d: %w", g, err))
		}
	}
	return errors.Join(errs...)
}

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
	"sync"
	"syscall"
	"time"

	"github.com/busconductors/bounty-run/core/events"
	"github.com/busconductors/bounty-run/core/runstore"
)

// ErrNoStart means the engine never emitted run_start in time.
var ErrNoStart = errors.New("engine did not start")

// Options are the user-selectable engine flags. Zero ints mean "engine default".
type Options struct {
	Target                                string
	Amass, TLS, Nikto, Nmap, Metis, Headi bool
	NmapFull                              bool // --nmap-full: all ports; only with Nmap
	Skip                                  []string
	Timeout, MaxParamURLs                 int
	// Proxy is a validated proxy URL ("" = none). It is deliberately NOT put
	// in Argv: SpawnEnv passes it as BOUNTY_RUN_PROXY (see ProxyEnvVar).
	Proxy string

	// Engine flags the desktop app exposes. Zero values emit no flag.
	Intensity               string // passive | active | intrusive
	Findomain               bool
	Resolvers               string
	DNSRate, Threads        int
	NoSubsCache, NoOAST     bool
	ScopeAllow, ScopeDeny   []string
	ScopeFile, UserAgent    string
	RateLimit               float64
	Retries                 *int // nil = engine default; 0 is a real value
	VerifyTLS               bool
	NoEvidence              bool
	EvidenceUnredacted      bool
	EvidenceMaxBody         int
	MaxHosts                int
	Wordlist                string
	NucleiSeverity          string
	NucleiC, NucleiTimeout  int
	RefreshIPIntel          bool
	IPIntelOffline, NoTrack bool

	// Engagement identity printed on the report cover. All optional.
	Client, Engagement, PreparedBy, Team string

	// Headers are "Name: value" strings. They may carry credentials, so they are
	// never put in Argv: SpawnEnvFor passes them as BOUNTY_RUN_HEADERS (a JSON
	// array). The engine reads that variable from a later release on.
	Headers []string
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

// Argv builds the engine command line (without the binary). It never contains
// the proxy, which travels in the environment (ProxyEnv).
func Argv(o Options, dir string) []string {
	a := []string{o.Target, "-o", dir, "--events", dir + "/events.jsonl", "--no-banner"}
	for _, f := range []struct {
		on   bool
		flag string
	}{{o.Amass, "--amass"}, {o.TLS, "--tls"}, {o.Nikto, "--nikto"}, {o.Nmap, "--nmap"}, {o.Metis, "--metis"}, {o.Headi, "--headi"}, {o.Nmap && o.NmapFull, "--nmap-full"}} {
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
	if o.Intensity != "" {
		a = append(a, "--intensity", o.Intensity)
	}
	if o.Findomain {
		a = append(a, "--findomain")
	}
	a = appendEq(a, "--resolvers", o.Resolvers)
	a = appendInt(a, "--dns-rate", o.DNSRate)
	if o.NoSubsCache {
		a = append(a, "--no-subs-cache")
	}
	a = appendInt(a, "--threads", o.Threads)
	if o.NoOAST {
		a = append(a, "--no-oast")
	}
	for _, r := range o.ScopeAllow {
		a = appendEq(a, "--scope-allow", r)
	}
	for _, r := range o.ScopeDeny {
		a = appendEq(a, "--scope-deny", r)
	}
	a = appendEq(a, "--scope-file", o.ScopeFile)
	a = appendEq(a, "--user-agent", o.UserAgent)
	a = appendEq(a, "--client", o.Client)
	a = appendEq(a, "--engagement", o.Engagement)
	a = appendEq(a, "--prepared-by", o.PreparedBy)
	a = appendEq(a, "--team", o.Team)
	if o.RateLimit > 0 {
		a = append(a, "--rate-limit", strconv.FormatFloat(o.RateLimit, 'g', -1, 64))
	}
	if o.Retries != nil && *o.Retries >= 0 {
		a = append(a, "--retries", strconv.Itoa(*o.Retries))
	}
	for _, f := range []struct {
		on   bool
		flag string
	}{{o.VerifyTLS, "--verify-tls"}, {o.NoEvidence, "--no-evidence"}, {o.EvidenceUnredacted, "--evidence-unredacted"}} {
		if f.on {
			a = append(a, f.flag)
		}
	}
	a = appendInt(a, "--evidence-max-body", o.EvidenceMaxBody)
	a = appendInt(a, "--max-hosts", o.MaxHosts)
	a = appendEq(a, "--wordlist", o.Wordlist)
	a = appendEq(a, "--nuclei-severity", o.NucleiSeverity)
	a = appendInt(a, "--nuclei-c", o.NucleiC)
	a = appendInt(a, "--nuclei-timeout", o.NucleiTimeout)
	for _, f := range []struct {
		on   bool
		flag string
	}{{o.RefreshIPIntel, "--refresh-ipintel"}, {o.IPIntelOffline, "--ipintel-offline"}, {o.NoTrack, "--no-track"}} {
		if f.on {
			a = append(a, f.flag)
		}
	}
	return a
}

// appendInt adds "flag n" when n > 0.
func appendInt(a []string, flag string, n int) []string {
	if n > 0 {
		return append(a, flag, strconv.Itoa(n))
	}
	return a
}

// appendEq adds "--flag=v" when v is non-empty. The single-element form keeps
// argparse from reading a value that starts with "-" as an option.
func appendEq(a []string, flag, v string) []string {
	if v != "" {
		return append(a, flag+"="+v)
	}
	return a
}

// PreviewArgv is the command line shown to the user before launch. It is
// exactly what Argv spawns; secrets (proxy, headers) are never in Argv.
func PreviewArgv(o Options, dir string) []string { return Argv(o, dir) }

// Spawn starts the engine in its own session with stdout/stderr going to
// dir/engine.log and stdin from /dev/null. A goroutine Waits on the child so it
// never lingers as a zombie while the TUI keeps running.
func Spawn(bin string, argv []string, dir string) (int, error) {
	return SpawnEnv(bin, argv, dir, nil)
}

// SpawnEnv is Spawn with extra environment entries appended to the parent's own
// (later entries win, so they override an inherited value of the same name). An
// inherited BOUNTY_RUN_HEADERS is always dropped so headers reach the engine
// only when extraEnv sets them for this launch.
func SpawnEnv(bin string, argv []string, dir string, extraEnv []string) (int, error) {
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
	env := make([]string, 0, len(os.Environ())+len(extraEnv))
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, HeadersEnvVar+"=") {
			env = append(env, e)
		}
	}
	cmd.Env = append(env, extraEnv...)
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

// LogTail returns the last n lines of dir/engine.log.
func LogTail(dir string, n int) string { return logTail(filepath.Join(dir, "engine.log"), n) }

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

// controlMu serializes writeControl: two quick key presses run two tea.Cmd
// goroutines, and an unserialized read-append-rename would drop a line.
var controlMu sync.Mutex

// writeControl writes via temp file + rename so the engine never sees a partial line.
func writeControl(dir, line string) error {
	controlMu.Lock()
	defer controlMu.Unlock()
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

// HardKill SIGKILLs the engine and the tool process groups listed in
// dir/pids (tools run in their own sessions). Because a dead engine's numbers
// may since have been reused, every signal is guarded:
//   - the engine's group is signalled only when the engine leads it
//     (PGID == PID, as for TUI-spawned engines); otherwise only the engine pid
//     is killed, and only while it is still the recorded process;
//   - a group is signalled only if it has a live member that started no
//     earlier than the engine (info.PIDStart);
//   - pgid <= 1 and the TUI's own group are never signalled. ESRCH is ignored.
func HardKill(info runstore.RunInfo, dir string) error {
	var groups []int
	var errs []error
	if info.PGID == info.PID {
		groups = append(groups, info.PGID)
	} else if info.PID > 1 && info.PID != os.Getpid() && runstore.Alive(info.PID, info.PIDStart) {
		if err := syscall.Kill(info.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Errorf("kill pid %d: %w", info.PID, err))
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, "pids")); err == nil {
		for _, l := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(l); err == nil {
				groups = append(groups, n)
			}
		}
	}
	self := syscall.Getpgrp() // never kill the TUI's own group
	for _, g := range groups {
		if g <= 1 || g == self || !runstore.GroupHasMemberSince(g, info.PIDStart) {
			continue
		}
		if err := syscall.Kill(-g, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			errs = append(errs, fmt.Errorf("kill pgid %d: %w", g, err))
		}
	}
	return errors.Join(errs...)
}

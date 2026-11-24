// Package runs starts, attaches to, controls and streams engine runs for the
// desktop app. It talks to the frontend only through a bridge.Emitter.
package runs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"bountyrun/core/engine"
	"bountyrun/core/events"
	"bountyrun/core/runstore"
	"bountyrun/core/textsafe"
	"bountyrun/desktop/internal/bridge"
)

// MaxActive is how many runs may be active at once (the TUI's cap).
const MaxActive = 3

// ChannelRunsChanged is emitted (with a nil payload) whenever the run list may
// have changed; the client then calls ListRuns.
const ChannelRunsChanged = "runs:changed"

// ErrCapReached means MaxActive runs are already running or launching.
var ErrCapReached = fmt.Errorf("%d runs are already active", MaxActive)

const (
	defaultLiveness = 500 * time.Millisecond
	infoRetries     = 20 // run.json is written non-atomically: re-read a partial one
	infoRetryDelay  = 50 * time.Millisecond
	logTailLines    = 20
	maxLogTailLines = 1000
)

var stageRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// Config configures a Service. Zero values select the defaults: Root from
// OutputsRoot, EngineBin from EngineBin (resolved at each start), a real
// clock and a 500 ms liveness poll.
type Config struct {
	Root             string
	EngineBin        string
	Emitter          bridge.Emitter
	Clock            Clock
	LivenessInterval time.Duration
}

// RunRef identifies a run the service launched.
type RunRef struct {
	ID  string `json:"id"`
	Dir string `json:"dir"`
}

// Snapshot is returned by Attach. Batches on run:<ID>:batch then replay the
// run's events from the start, so the client clears its view first. Run is the
// run's discovered state, when run.json could be listed.
type Snapshot struct {
	ID  string        `json:"id"`
	Dir string        `json:"dir"`
	Run *runstore.Run `json:"run,omitempty"`
}

// DeadInfo is the payload of run:<id>:dead, sent once when an attached run's
// engine process is gone and every batch of its events (replay included) has
// been emitted; no batch follows it. Status is the run's final status (ok, failed,
// cancelled, crashed, incompatible).
type DeadInfo struct {
	Status string `json:"status"`
}

// LaunchError is a start whose engine never emitted run_start. It wraps
// engine.ErrExited (the engine quit, e.g. a usage error: exit 2) or
// engine.ErrNoStart (it timed out and was stopped). Tail is the sanitized
// end of engine.log; the run dir is kept so it can be inspected.
type LaunchError struct {
	Dir     string
	Tail    string
	Outcome string // for a timeout: how stopping the engine went
	Err     error
}

func (e *LaunchError) Error() string {
	msg := "engine exited before starting"
	if errors.Is(e.Err, engine.ErrNoStart) {
		msg = "engine did not start in time — " + e.Outcome
	}
	return msg + "\nengine.log tail:\n" + e.Tail
}

func (e *LaunchError) Unwrap() error { return e.Err }

// Service is the run backend. All methods are safe for concurrent use.
type Service struct {
	root     string
	bin      string
	em       bridge.Emitter
	clk      Clock
	liveness time.Duration
	store    *runstore.Store

	mu        sync.Mutex
	launching int                    // starts between reservation and WaitLaunch
	attached  map[string]*attachment // by run dir
}

type attachment struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// New returns a Service. It fails only when the outputs root cannot be made.
func New(cfg Config) (*Service, error) {
	if cfg.Emitter == nil {
		return nil, errors.New("runs: nil Emitter")
	}
	root := cfg.Root
	if root == "" {
		r, err := OutputsRoot()
		if err != nil {
			return nil, err
		}
		root = r
	} else {
		r, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		root = r
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, err
		}
	}
	s := &Service{
		root: root, bin: cfg.EngineBin, em: cfg.Emitter, clk: cfg.Clock,
		liveness: cfg.LivenessInterval, store: runstore.NewStore(root),
		attached: map[string]*attachment{},
	}
	if s.clk == nil {
		s.clk = realClock{}
	}
	if s.liveness <= 0 {
		s.liveness = defaultLiveness
	}
	return s, nil
}

// Root is the outputs root runs are written under.
func (s *Service) Root() string { return s.root }

// RunID is the stable, channel-safe id of the run in dir.
func RunID(dir string) string {
	h := sha256.Sum256([]byte(filepath.Clean(dir)))
	return hex.EncodeToString(h[:8])
}

// StartRun validates opts, reserves a slot under MaxActive, creates the run
// dir, spawns the engine (secrets only in its environment, BOUNTY_RUN_DATA set
// to the outputs root) and waits for run_start. It returns ErrCapReached when
// the cap is taken and a *LaunchError when the engine never started.
func (s *Service) StartRun(opts engine.Options) (RunRef, error) {
	target, err := engine.NormalizeTarget(opts.Target)
	if err != nil {
		return RunRef{}, err
	}
	opts.Target = target
	if strings.TrimSpace(opts.Proxy) != "" {
		p, err := engine.ParseProxy(opts.Proxy)
		if err != nil {
			return RunRef{}, fmt.Errorf("invalid proxy: %w", err)
		}
		opts.Proxy = p
	} else {
		opts.Proxy = ""
	}
	bin := s.bin
	if bin == "" {
		if bin, err = EngineBin(); err != nil {
			return RunRef{}, err
		}
	}
	if err := checkEngine(bin); err != nil {
		return RunRef{}, fmt.Errorf("engine: %w", err)
	}

	if err := s.reserve(); err != nil {
		return RunRef{}, err
	}
	// Released only after WaitLaunch: until run_start the engine may have no
	// run.json, so Discover alone would not count it.
	defer s.release()

	dir, err := engine.NewRunDir(s.root, target, time.Now())
	if err != nil {
		return RunRef{}, err
	}
	env := append(engine.SpawnEnvFor(opts), "BOUNTY_RUN_DATA="+s.root)
	pid, err := engine.SpawnEnv(bin, engine.Argv(opts, dir), dir, env)
	if err != nil {
		_ = os.RemoveAll(dir) // the leaf just made; no phantom run
		return RunRef{}, err
	}
	// SpawnEnv uses setsid, so the engine leads its own group.
	info := runstore.RunInfo{Dir: dir, PID: pid, PGID: pid}
	started, stErr := runstore.PIDStart(pid)
	info.PIDStart = started
	if err := engine.WaitLaunch(info, engine.LaunchTimeout(opts)); err != nil {
		le := &LaunchError{Dir: dir, Err: engine.ErrExited}
		if errors.Is(err, engine.ErrNoStart) {
			le.Err, le.Outcome = engine.ErrNoStart, "stopped"
			if stErr == nil { // without a start time nothing is safe to signal
				if kerr := engine.HardKill(info, dir); kerr != nil {
					le.Outcome = "stop failed: " + kerr.Error()
				}
			}
		}
		le.Tail = sanitizedTail(dir, logTailLines)
		return RunRef{}, le
	}
	s.em.Emit(ChannelRunsChanged, nil)
	return RunRef{ID: RunID(dir), Dir: dir}, nil
}

// reserve takes a launch slot if running plus launching runs leave room.
func (s *Service) reserve() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	runs, err := s.store.Discover()
	if err != nil {
		return err
	}
	if runstore.ActiveCount(runs)+s.launching >= MaxActive {
		return ErrCapReached
	}
	s.launching++
	return nil
}

func (s *Service) release() {
	s.mu.Lock()
	s.launching--
	s.mu.Unlock()
}

// ListRuns returns every run under the outputs root, running ones first.
func (s *Service) ListRuns() ([]runstore.Run, error) { return s.store.Discover() }

// Attach starts streaming the run in dir: batches on run:<id>:batch (replayed
// from the start of events.jsonl, then live) and run:<id>:dead once its engine
// is gone. Attaching to an attached run restarts the replay.
func (s *Service) Attach(dir string) (Snapshot, error) {
	dir, err := s.runDir(dir)
	if err != nil {
		return Snapshot{}, err
	}
	info, err := readInfoRetry(dir)
	if err != nil {
		return Snapshot{}, err
	}
	s.Detach(dir)
	id := RunID(dir)
	snap := Snapshot{ID: id, Dir: dir}
	if r, ok := s.findRun(dir); ok {
		snap.Run = &r
	}

	ctx, cancel := context.WithCancel(context.Background())
	a := &attachment{cancel: cancel, done: make(chan struct{})}
	s.mu.Lock()
	if old := s.attached[dir]; old != nil { // a concurrent Attach won the race
		old.cancel()
		<-old.done
	}
	s.attached[dir] = a
	s.mu.Unlock()

	go s.follow(ctx, a, dir, id, info)
	return snap, nil
}

// follow tails the run's events into the coalescer until ctx is done.
func (s *Service) follow(ctx context.Context, a *attachment, dir, id string, info runstore.RunInfo) {
	defer close(a.done)
	// A tiny buffer: queued messages are not yet clipped for display, and an
	// event line can be up to 16 MiB.
	ch := make(chan any, 1)
	path := filepath.Join(dir, "events.jsonl")
	tailDone := make(chan struct{})
	go func() {
		defer close(tailDone)
		defer close(ch) // tells pump the tail stopped (e.g. incompatible version)
		events.TailWithEOF(ctx, path, ch)
	}()
	defer func() { <-tailDone }()

	flush := s.clk.NewTicker(FlushInterval)
	defer flush.Stop()
	live := s.clk.NewTicker(s.liveness)
	defer live.Stop()
	batchCh, deadCh := "run:"+id+":batch", "run:"+id+":dead"
	lv := &liveness{
		c:     live.C(),
		alive: func() bool { return runstore.Alive(info.PID, info.PIDStart) },
		size: func() (int64, bool) {
			fi, err := os.Stat(path)
			if err != nil {
				return 0, false
			}
			return fi.Size(), true
		},
		report: func() {
			st := string(runstore.Crashed)
			if r, ok := s.findRun(dir); ok && r.Status != runstore.Running {
				st = string(r.Status)
			}
			s.em.Emit(deadCh, DeadInfo{Status: st})
			s.em.Emit(ChannelRunsChanged, nil)
		},
	}
	pump(ctx, ch, flush.C(), func(b Batch) { s.em.Emit(batchCh, b) }, lv)
}

// Detach stops streaming dir. The engine keeps running. Safe to repeat.
func (s *Service) Detach(dir string) {
	if d, err := s.runDir(dir); err == nil {
		dir = d
	}
	s.mu.Lock()
	a := s.attached[dir]
	delete(s.attached, dir)
	s.mu.Unlock()
	if a != nil {
		a.cancel()
		<-a.done // no batch is emitted after Detach returns
	}
}

// Close detaches every run. Engines keep running.
func (s *Service) Close() {
	s.mu.Lock()
	dirs := make([]string, 0, len(s.attached))
	for d := range s.attached {
		dirs = append(dirs, d)
	}
	s.mu.Unlock()
	for _, d := range dirs {
		s.Detach(d)
	}
}

// Skip asks the engine to skip stage.
func (s *Service) Skip(dir, stage string) error {
	dir, err := s.runDir(dir)
	if err != nil {
		return err
	}
	if !stageRE.MatchString(stage) { // a newline would inject a control line
		return fmt.Errorf("invalid stage %q", textsafe.OneLine(stage))
	}
	return engine.Skip(dir, stage)
}

// Cancel asks the engine to cancel the run.
func (s *Service) Cancel(dir string) error {
	dir, err := s.runDir(dir)
	if err != nil {
		return err
	}
	return engine.Cancel(dir)
}

// HardKill SIGKILLs the engine and its tool process groups (guarded against
// PID reuse by engine.HardKill).
func (s *Service) HardKill(dir string) error {
	dir, err := s.runDir(dir)
	if err != nil {
		return err
	}
	info, err := readInfoRetry(dir)
	if err != nil {
		return err
	}
	err = engine.HardKill(info, dir)
	s.em.Emit(ChannelRunsChanged, nil)
	return err
}

// EngineLogTail returns the last n (1..1000) lines of dir/engine.log,
// sanitized for display, or "" for a dir outside the outputs root.
func (s *Service) EngineLogTail(dir string, n int) string {
	dir, err := s.runDir(dir)
	if err != nil {
		return ""
	}
	return sanitizedTail(dir, min(max(n, 1), maxLogTailLines))
}

func sanitizedTail(dir string, n int) string {
	lines := strings.Split(engine.LogTail(dir, n), "\n")
	for i, l := range lines {
		lines[i] = display(l)
	}
	return strings.Join(lines, "\n")
}

// runDir checks that dir is a run directory root/<target>/<stamp> (not a
// symlink) and returns it cleaned. Every control goes through it, so the
// frontend cannot point the service at arbitrary paths.
func (s *Service) runDir(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("run dir %q is not absolute", dir)
	}
	dir = filepath.Clean(dir)
	rel, err := filepath.Rel(s.root, dir)
	if err != nil {
		return "", err
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 2 || parts[0] == ".." || parts[0] == "." || parts[1] == ".." {
		return "", fmt.Errorf("%q is not a run directory under %s", dir, s.root)
	}
	for _, p := range []string{filepath.Dir(dir), dir} {
		fi, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if !fi.IsDir() {
			return "", fmt.Errorf("%q is not a run directory", p)
		}
	}
	return dir, nil
}

func (s *Service) findRun(dir string) (runstore.Run, bool) {
	runs, err := s.store.Discover()
	if err != nil {
		return runstore.Run{}, false
	}
	for _, r := range runs {
		if r.Info.Dir == dir {
			return r, true
		}
	}
	return runstore.Run{}, false
}

// readInfoRetry reads dir/run.json, retrying briefly while it is missing or
// only partly written.
func readInfoRetry(dir string) (runstore.RunInfo, error) {
	var err error
	for i := 0; i < infoRetries; i++ {
		var info runstore.RunInfo
		if info, err = runstore.ReadInfo(dir); err == nil {
			return info, nil
		}
		time.Sleep(infoRetryDelay)
	}
	return runstore.RunInfo{}, fmt.Errorf("read run.json: %w", err)
}

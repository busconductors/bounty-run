// Package runstore discovers engine runs on disk and derives their status.
package runstore

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"bountyrun/tui/internal/events"
)

// RunInfo is the content of run.json plus its directory.
type RunInfo struct {
	Dir, Target string
	PID, PGID   int
	PIDStart    int64
	Started     time.Time
	Flags       map[string]any
}

// Status is a run's derived state.
type Status string

const (
	Running      Status = "running"
	OK           Status = "ok"
	Cancelled    Status = "cancelled"
	Failed       Status = "failed"
	Crashed      Status = "crashed"
	Incompatible Status = "incompatible"
)

// Run is a discovered run with replay-derived state.
type Run struct {
	Info         RunInfo
	Status       Status
	CurrentStage string
	Elapsed      time.Duration
	Sev          map[string]int
	Ended        bool
}

type runJSON struct {
	PID      int            `json:"pid"`
	PGID     int            `json:"pgid"`
	PIDStart int64          `json:"pid_start"`
	Target   string         `json:"target"`
	Flags    map[string]any `json:"flags"`
	Started  int64          `json:"started"`
}

func readInfo(path string) (RunInfo, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RunInfo{}, err
	}
	var rj runJSON
	if err := json.Unmarshal(b, &rj); err != nil {
		return RunInfo{}, err
	}
	dir := filepath.Dir(path)
	target := rj.Target
	if target == "" {
		target = filepath.Base(filepath.Dir(dir))
	}
	return RunInfo{
		Dir: dir, Target: target, PID: rj.PID, PGID: rj.PGID,
		PIDStart: rj.PIDStart, Started: time.UnixMilli(rj.Started), Flags: rj.Flags,
	}, nil
}

// ReadInfo reads dir/run.json.
func ReadInfo(dir string) (RunInfo, error) { return readInfo(filepath.Join(dir, "run.json")) }

// Discover scans root/*/*/run.json and replays each events.jsonl once.
func Discover(root string) ([]Run, error) { return NewStore(root).Discover() }

// Store discovers runs under root and caches replay state between calls: an
// ended run (run_end is final) is never re-read, and a live run's
// events.jsonl is decoded only from where the previous call stopped.
type Store struct {
	root  string
	mu    sync.Mutex
	cache map[string]*replayState // keyed by run.json path
}

// NewStore returns an empty Store for root.
func NewStore(root string) *Store {
	return &Store{root: root, cache: map[string]*replayState{}}
}

// replayState is the accumulated replay of one run's events.jsonl.
type replayState struct {
	info         RunInfo
	off          int64  // bytes of events.jsonl consumed so far
	partial      []byte // trailing bytes without '\n', held back
	stack        []string
	sev          map[string]int
	endEv        *events.Event
	incompatible bool
	final        *Run // set once run_end was seen
}

// Discover scans root/*/*/run.json and returns every run, running ones first,
// then newest first.
func (s *Store) Discover() ([]Run, error) {
	paths, err := filepath.Glob(filepath.Join(s.root, "*", "*", "run.json"))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	seen := make(map[string]bool, len(paths))
	runs := make([]Run, 0, len(paths))
	for _, p := range paths {
		seen[p] = true
		st := s.cache[p]
		if st == nil {
			info, err := readInfo(p)
			if err != nil {
				continue // retried on the next call
			}
			st = &replayState{info: info, sev: map[string]int{}}
			s.cache[p] = st
		}
		if st.final == nil {
			st.advance()
		}
		runs = append(runs, st.run(now))
	}
	for p := range s.cache {
		if !seen[p] {
			delete(s.cache, p)
		}
	}
	sort.SliceStable(runs, func(i, j int) bool {
		ri, rj := runs[i].Status == Running, runs[j].Status == Running
		if ri != rj {
			return ri
		}
		return runs[i].Info.Started.After(runs[j].Info.Started)
	})
	return runs, nil
}

// advance decodes the bytes appended to events.jsonl since the last call.
// A trailing line without '\n' is kept back until it completes.
func (st *replayState) advance() {
	f, err := os.Open(filepath.Join(st.info.Dir, "events.jsonl"))
	if err != nil {
		return
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() < st.off {
		// truncated or replaced: start over
		info := st.info
		*st = replayState{info: info, sev: map[string]int{}}
	}
	if _, err := f.Seek(st.off, io.SeekStart); err != nil {
		return
	}
	br := bufio.NewReaderSize(f, 64*1024)
	for {
		chunk, rerr := br.ReadBytes('\n')
		st.off += int64(len(chunk))
		if len(chunk) > 0 {
			if chunk[len(chunk)-1] != '\n' {
				st.partial = append(st.partial, chunk...)
			} else {
				line := chunk
				if len(st.partial) > 0 {
					line = append(st.partial, chunk...)
					st.partial = nil
				}
				st.apply(line)
			}
		}
		if rerr != nil {
			return
		}
	}
}

func (st *replayState) apply(line []byte) {
	ev, derr := events.Decode(line)
	switch {
	case errors.Is(derr, events.ErrVersion):
		st.incompatible = true
	case derr != nil:
	default:
		switch ev.Type {
		case "stage_start":
			st.stack = append(st.stack, ev.Stage)
		case "stage_end":
			for i := len(st.stack) - 1; i >= 0; i-- {
				if st.stack[i] == ev.Stage {
					st.stack = append(st.stack[:i], st.stack[i+1:]...)
					break
				}
			}
		case "finding":
			st.sev[ev.Severity]++
		case "run_end":
			e := ev
			st.endEv = &e
		}
	}
}

// run derives the run's current state. Once run_end was seen the result is
// cached as final.
func (st *replayState) run(now time.Time) Run {
	if st.final != nil {
		r := *st.final
		r.Sev = maps.Clone(r.Sev) // callers may hold it across later calls
		return r
	}
	r := Run{Info: st.info, Sev: maps.Clone(st.sev)}
	if len(st.stack) > 0 {
		r.CurrentStage = st.stack[len(st.stack)-1]
	}
	switch {
	case st.incompatible:
		r.Status = Incompatible
		r.Elapsed = now.Sub(st.info.Started)
	case st.endEv != nil:
		r.Ended = true
		r.Status = Status(st.endEv.Status)
		if st.endEv.Totals != nil {
			r.Sev = maps.Clone(st.endEv.Totals)
		}
		r.CurrentStage = ""
		r.Elapsed = time.UnixMilli(st.endEv.T).Sub(st.info.Started)
	case Alive(st.info.PID, st.info.PIDStart):
		r.Status = Running
		r.Elapsed = now.Sub(st.info.Started)
	default:
		r.Status = Crashed
		r.Elapsed = now.Sub(st.info.Started)
	}
	if r.Elapsed < 0 {
		r.Elapsed = 0
	}
	if r.Ended {
		final := r
		st.final = &final
		st.stack, st.partial = nil, nil
	}
	return r
}

// ActiveCount returns how many runs are Running.
func ActiveCount(runs []Run) int {
	n := 0
	for _, r := range runs {
		if r.Status == Running {
			n++
		}
	}
	return n
}

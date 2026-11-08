// Package runstore discovers engine runs on disk and derives their status.
package runstore

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
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
func Discover(root string) ([]Run, error) {
	paths, err := filepath.Glob(filepath.Join(root, "*", "*", "run.json"))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	runs := make([]Run, 0, len(paths))
	for _, p := range paths {
		info, err := readInfo(p)
		if err != nil {
			continue
		}
		runs = append(runs, replay(info, now))
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

func replay(info RunInfo, now time.Time) Run {
	r := Run{Info: info, Sev: map[string]int{}}
	var stack []string
	var endEv *events.Event
	incompatible := false

	if f, err := os.Open(filepath.Join(info.Dir, "events.jsonl")); err == nil {
		br := bufio.NewReaderSize(f, 64*1024)
		for {
			line, rerr := br.ReadBytes('\n')
			if len(line) > 0 {
				ev, derr := events.Decode(line)
				switch {
				case errors.Is(derr, events.ErrVersion):
					incompatible = true
				case derr != nil:
				default:
					switch ev.Type {
					case "stage_start":
						stack = append(stack, ev.Stage)
					case "stage_end":
						for i := len(stack) - 1; i >= 0; i-- {
							if stack[i] == ev.Stage {
								stack = append(stack[:i], stack[i+1:]...)
								break
							}
						}
					case "finding":
						r.Sev[ev.Severity]++
					case "run_end":
						e := ev
						endEv = &e
					}
				}
			}
			if rerr != nil {
				if rerr != io.EOF {
					break
				}
				break
			}
		}
		f.Close()
	}

	if len(stack) > 0 {
		r.CurrentStage = stack[len(stack)-1]
	}
	switch {
	case incompatible:
		r.Status = Incompatible
		r.Elapsed = now.Sub(info.Started)
	case endEv != nil:
		r.Ended = true
		r.Status = Status(endEv.Status)
		if endEv.Totals != nil {
			r.Sev = endEv.Totals
		}
		r.CurrentStage = ""
		r.Elapsed = time.UnixMilli(endEv.T).Sub(info.Started)
	case Alive(info.PID, info.PIDStart):
		r.Status = Running
		r.Elapsed = now.Sub(info.Started)
	default:
		r.Status = Crashed
		r.Elapsed = now.Sub(info.Started)
	}
	if r.Elapsed < 0 {
		r.Elapsed = 0
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

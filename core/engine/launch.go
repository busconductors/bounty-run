package engine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"bountyrun/core/runstore"
)

// ErrExited means the engine process ended before it emitted run_start.
var ErrExited = errors.New("engine exited before starting")

const (
	launchTimeout      = 3 * time.Second
	launchTimeoutProxy = 20 * time.Second // proxy preflight probes can be slow
)

// LaunchTimeout is how long to wait for run_start: preflight through a proxy
// can legitimately take far longer than a direct one.
func LaunchTimeout(o Options) time.Duration {
	if o.Proxy != "" {
		return launchTimeoutProxy
	}
	return launchTimeout
}

// WaitLaunch waits up to timeout for the engine described by info to emit
// run_start. It returns nil on run_start, an error wrapping ErrExited (with the
// engine.log tail) as soon as the process is gone, and one wrapping ErrNoStart
// at the deadline. After seeing an exit it checks for run_start once more, so a
// short-lived but successful engine is not reported as a failure.
func WaitLaunch(info runstore.RunInfo, timeout time.Duration) error {
	events := filepath.Join(info.Dir, "events.jsonl")
	deadline := time.Now().Add(timeout)
	for {
		if hasRunStart(events) {
			return nil
		}
		if procGone(info.PID, info.PIDStart) {
			if hasRunStart(events) {
				return nil
			}
			return fmt.Errorf("%w; engine.log tail:\n%s", ErrExited, LogTail(info.Dir, 20))
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%w within %s; engine.log tail:\n%s", ErrNoStart, timeout, LogTail(info.Dir, 20))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// procGone reports whether the process started at pidStart has ended. A zombie
// (exited, not yet reaped) still has a /proc entry, so state Z and X count as
// gone, as does a missing entry or a different start time (PID reuse).
func procGone(pid int, pidStart int64) bool {
	if pid <= 0 {
		return true
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return true
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return true
	}
	if f[0] == "Z" || f[0] == "X" {
		return true
	}
	st, err := strconv.ParseInt(f[19], 10, 64)
	return err != nil || st != pidStart
}

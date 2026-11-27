//go:build darwin

package runstore

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The run-list refresh calls Alive per non-ended run every second, and HardKill
// calls GroupHasMemberSince; one ps per call would mean N forks a second. Both
// read from a single `ps -ax` listing cached for a short TTL, so a refresh of N
// runs costs ~1 ps call, not N (design doc lines 117-119). A just-forked pid is
// not yet in that snapshot, so the two places that must see one immediately read
// fresh instead: PIDStart (launch records pid_start) and Alive's cache-miss
// fallback.
var (
	psMu  sync.Mutex
	psAt  time.Time
	psOut []byte
)

const psSnapshotTTL = time.Second

// psAll runs one `ps -ax -o pid=,pgid=,stat=,lstart=` listing, each line
// "pid pgid stat Day Mon DD HH:MM:SS YYYY": three fixed leading columns, then
// the lstart date as the remainder. Forced to UTC/C so lstart matches the
// engine's parse.
func psAll() ([]byte, error) {
	cmd := exec.Command("/bin/ps", "-ax", "-o", "pid=,pgid=,stat=,lstart=")
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	return cmd.Output()
}

// psSnapshot returns the cached ps listing, refreshing it when older than the
// TTL. nil on error.
func psSnapshot() []byte {
	psMu.Lock()
	defer psMu.Unlock()
	if psOut != nil && time.Since(psAt) < psSnapshotTTL {
		return psOut
	}
	out, err := psAll()
	if err != nil {
		return nil
	}
	psOut, psAt = out, time.Now()
	return out
}

// psSnapshotFresh forces a new ps listing, bypassing the TTL (and refreshing the
// cache). Used on a cache-miss re-check where a just-spawned process may not yet
// be in the cached listing. nil on error.
func psSnapshotFresh() []byte {
	psMu.Lock()
	defer psMu.Unlock()
	out, err := psAll()
	if err != nil {
		return nil
	}
	psOut, psAt = out, time.Now()
	return out
}

// freshProbeCount counts probeFresh invocations; test observability only, used
// to assert that confirmed-dead pids are not re-probed (the Alive memo).
var freshProbeCount atomic.Int64

// probeFresh reads pid's start time with a point-in-time `ps -p`, bypassing the
// snapshot cache. Whole-second resolution (there is no /proc). It is tri-state:
//   - (st, found=true,  ok=true):  pid exists, st is its start time
//   - (0,  found=false, ok=true):  ps ran and the pid is absent — authoritative
//   - (0,  found=false, ok=false): ps itself could not run (transient) — the
//     caller must NOT treat this as a confirmed death (never memoise it)
func probeFresh(pid int) (st int64, found, ok bool) {
	freshProbeCount.Add(1)
	cmd := exec.Command("/bin/ps", "-o", "lstart=", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return 0, false, true // ps ran, exited non-zero: pid absent
		}
		return 0, false, false // ps could not be run: transient, not authoritative
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return 0, false, true // ran, empty: absent
	}
	st, perr := ParseLstart(s)
	if perr != nil {
		return 0, false, false // unparsable: not authoritative
	}
	return st, true, true
}

// pidStartFresh reads pid's start time via a point-in-time ps. Used where a
// just-forked pid must be seen immediately: PIDStart (launch, Step-D cross-
// check). A missing pid (or a transient ps failure) yields os.ErrProcessDone.
func pidStartFresh(pid int) (int64, error) {
	if st, found, ok := probeFresh(pid); ok && found {
		return st, nil
	}
	return 0, os.ErrProcessDone
}

// pidStartCached returns pid's start time from the cached ps snapshot and
// whether it was present. Absent means exited OR started within the snapshot's
// TTL — the caller (Alive) disambiguates with a fresh read.
func pidStartCached(pid int) (int64, bool) {
	out := psSnapshot()
	if out == nil {
		return 0, false
	}
	want := strconv.Itoa(pid)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[0] != want { // pid + pgid + stat + 5 lstart tokens
			continue
		}
		st, err := ParseLstart(strings.Join(f[3:], " "))
		if err != nil {
			return 0, false
		}
		return st, true
	}
	return 0, false
}

// PIDStart returns pid's start time as epoch seconds via a fresh ps — correct
// even for a pid younger than the snapshot TTL (launch records pid_start here;
// the Step-D cross-check reads it here). The per-second N-run liveness uses
// Alive (snapshot-backed) instead, so it stays at ~1 ps/refresh.
func PIDStart(pid int) (int64, error) {
	return pidStartFresh(pid)
}

// deadMemo records (pid, start) pairs a fresh probe has authoritatively found
// gone. Liveness is monotonic — that exact process never resurrects, and a
// reused pid carries a different start time — so once dead, always dead. The
// per-second run-list refresh calls Alive for every non-ended run, including
// crashed ones whose pid is permanently absent from the snapshot; without this
// memo each such run would fork a fresh ps every tick. Only authoritative deaths
// are recorded (never a transient ps failure), so a live run is never poisoned.
var (
	deadMu   sync.Mutex
	deadMemo = map[deadKey]struct{}{}
)

type deadKey struct {
	pid   int
	start int64
}

// Alive reports whether pid exists with start time == pidStart (guards against
// PID reuse). Fast path: the cached `ps -ax` snapshot shared by the per-second
// refresh of N runs. On a cache miss — a just-started or just-exited pid — it
// falls back to one fresh ps (so a live just-launched run is never reported dead,
// F2), memoising an authoritative death so a permanently-gone pid is not
// re-forked every tick.
func Alive(pid int, pidStart int64) bool {
	if pid <= 0 {
		return false
	}
	if st, ok := pidStartCached(pid); ok {
		return st == pidStart
	}
	key := deadKey{pid, pidStart}
	deadMu.Lock()
	_, dead := deadMemo[key]
	deadMu.Unlock()
	if dead {
		return false
	}
	st, found, ok := probeFresh(pid)
	if !ok {
		return false // transient ps failure: not alive this tick, but don't memoise
	}
	if found && st == pidStart {
		return true
	}
	deadMu.Lock()
	deadMemo[key] = struct{}{}
	deadMu.Unlock()
	return false
}

// groupHasMemberSinceIn scans one ps listing for a live (non-zombie) process
// whose process group is pgid and whose start time is >= since.
func groupHasMemberSinceIn(out []byte, pgid int, since int64) bool {
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 {
			continue
		}
		gp, err := strconv.Atoi(f[1])
		if err != nil || gp != pgid || strings.HasPrefix(f[2], "Z") {
			continue
		}
		if st, err := ParseLstart(strings.Join(f[3:], " ")); err == nil && st >= since {
			return true
		}
	}
	return false
}

// GroupHasMemberSince reports whether some live process has process group pgid
// and a start time >= since. Zombies (stat starting "Z") are skipped, matching
// the Linux impl. It reads a FRESH ps, never the cached snapshot: its only
// caller, HardKill, is one-shot (cancel), and a stale snapshot is wrong in both
// directions here — it would miss a just-spawned child group (orphan on a fast
// cancel) and, worse, report a just-killed group as still alive (signal a dead
// group → EPERM). Freshness is the F3a root-cause fix.
func GroupHasMemberSince(pgid int, since int64) bool {
	if pgid <= 0 {
		return false
	}
	return groupHasMemberSinceIn(psSnapshotFresh(), pgid, since)
}

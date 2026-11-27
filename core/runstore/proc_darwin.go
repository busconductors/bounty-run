//go:build darwin

package runstore

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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

// pidStartFresh reads pid's start time with a point-in-time `ps -p`, bypassing
// the snapshot cache. Whole-second resolution (there is no /proc). Used wherever
// a just-forked pid must be seen immediately: PIDStart (launch, Step-D cross-
// check) and Alive's cache-miss fallback. A missing pid yields os.ErrProcessDone.
func pidStartFresh(pid int) (int64, error) {
	cmd := exec.Command("/bin/ps", "-o", "lstart=", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return 0, os.ErrProcessDone // no such process
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return 0, os.ErrProcessDone
	}
	return ParseLstart(s)
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

// Alive reports whether pid exists with start time == pidStart (guards against
// PID reuse). Fast path: the cached `ps -ax` snapshot shared by the per-second
// refresh of N runs. On a cache miss — a just-started or just-exited pid — it
// falls back to one fresh ps, so a live just-launched run is never reported dead
// (F2) and a real exit is still confirmed.
func Alive(pid int, pidStart int64) bool {
	if pid <= 0 {
		return false
	}
	if st, ok := pidStartCached(pid); ok {
		return st == pidStart
	}
	st, err := pidStartFresh(pid)
	return err == nil && st == pidStart
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

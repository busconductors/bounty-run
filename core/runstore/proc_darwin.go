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

// The run-list refresh calls Alive -> PIDStart per non-ended run every second,
// and HardKill calls GroupHasMemberSince; one ps per call would mean N forks a
// second. Both read from a single `ps -ax` listing cached for a short TTL, so a
// refresh of N runs costs ~1 ps call, not N (design doc lines 117-119). The
// launch-time check (core/engine) deliberately does NOT use this: a just-forked
// pid must be read fresh, never from a snapshot up to a second stale.
var (
	psMu  sync.Mutex
	psAt  time.Time
	psOut []byte
)

const psSnapshotTTL = time.Second

// psSnapshot returns one `ps -ax -o pid=,pgid=,stat=,lstart=` listing, each line
// "pid pgid stat Day Mon DD HH:MM:SS YYYY": three fixed leading columns, then
// the lstart date as the remainder. Forced to UTC/C so lstart matches the
// engine's parse.
func psSnapshot() []byte {
	psMu.Lock()
	defer psMu.Unlock()
	if psOut != nil && time.Since(psAt) < psSnapshotTTL {
		return psOut
	}
	cmd := exec.Command("/bin/ps", "-ax", "-o", "pid=,pgid=,stat=,lstart=")
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	psOut, psAt = out, time.Now()
	return out
}

// PIDStart returns pid's start time as epoch seconds, read from the cached ps
// snapshot (whole-second resolution on darwin; there is no /proc). A pid absent
// from the snapshot — exited, or started within the last snapshot's TTL — yields
// os.ErrProcessDone, which Alive reads as not-alive.
func PIDStart(pid int) (int64, error) {
	out := psSnapshot()
	if out == nil {
		return 0, os.ErrProcessDone
	}
	want := strconv.Itoa(pid)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 || f[0] != want { // pid + pgid + stat + 5 lstart tokens
			continue
		}
		return ParseLstart(strings.Join(f[3:], " "))
	}
	return 0, os.ErrProcessDone
}

// GroupHasMemberSince reports whether some live process has process group pgid
// and a start time >= since. Zombies (stat starting "Z") are skipped, matching
// the Linux impl.
func GroupHasMemberSince(pgid int, since int64) bool {
	if pgid <= 0 {
		return false
	}
	out := psSnapshot()
	if out == nil {
		return false
	}
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

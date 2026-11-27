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

// psEnv forces ps to emit times in UTC and the C locale, so lstart parses to a
// value that matches the engine's _pid_start (runner/events.py).
func psEnv() []string {
	return append(os.Environ(), "TZ=UTC", "LC_ALL=C")
}

// PIDStart returns pid's start time as epoch seconds, read from `ps -o lstart=`
// (whole-second resolution on darwin; there is no /proc).
func PIDStart(pid int) (int64, error) {
	cmd := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(pid))
	cmd.Env = psEnv()
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	return parseLstart(strings.TrimSpace(string(out)))
}

// A refresh of the run list calls Alive/GroupHasMemberSince per non-ended run;
// one ps each would be slow. Cache one `ps -ax` listing for a short TTL so a
// refresh of N runs costs ~1 ps call.
var (
	psMu  sync.Mutex
	psAt  time.Time
	psOut []byte
)

const psSnapshotTTL = time.Second

func psGroupSnapshot() []byte {
	psMu.Lock()
	defer psMu.Unlock()
	if psOut != nil && time.Since(psAt) < psSnapshotTTL {
		return psOut
	}
	cmd := exec.Command("ps", "-ax", "-o", "pid=,pgid=,stat=,lstart=")
	cmd.Env = psEnv()
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	psOut, psAt = out, time.Now()
	return out
}

// GroupHasMemberSince reports whether some live process has process group pgid
// and a start time >= since. Zombies (stat starting "Z") are skipped, matching
// the Linux impl. Each line is "pid pgid stat Day Mon DD HH:MM:SS YYYY": three
// fixed leading columns, then the lstart date as the remainder.
func GroupHasMemberSince(pgid int, since int64) bool {
	if pgid <= 0 {
		return false
	}
	out := psGroupSnapshot()
	if out == nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 8 { // pid + pgid + stat + 5 lstart tokens
			continue
		}
		gp, err := strconv.Atoi(f[1])
		if err != nil || gp != pgid || strings.HasPrefix(f[2], "Z") {
			continue
		}
		if st, err := parseLstart(strings.Join(f[3:], " ")); err == nil && st >= since {
			return true
		}
	}
	return false
}

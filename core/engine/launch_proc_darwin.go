//go:build darwin

package engine

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/busconductors/bounty-run/core/runstore"
)

// procGone queries the process fresh via ps (there is no /proc on macOS, and the
// launch check must not read a just-forked pid from a stale snapshot). A zombie
// (stat "Z"), a missing process (ps exits non-zero), or a different start time
// (PID reuse) counts as gone — matching the linux semantics. lstart is parsed by
// the one shared parser so this check agrees with the engine's recorded value.
func procGone(pid int, pidStart int64) bool {
	if pid <= 0 {
		return true
	}
	cmd := exec.Command("ps", "-o", "stat=,lstart=", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return true // no such process
	}
	f := strings.Fields(string(out))
	if len(f) < 6 { // stat + 5 lstart tokens
		return true
	}
	if strings.HasPrefix(f[0], "Z") {
		return true // zombie
	}
	st, err := runstore.ParseLstart(strings.Join(f[1:], " "))
	return err != nil || st != pidStart
}

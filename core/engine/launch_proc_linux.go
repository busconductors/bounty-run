//go:build linux

package engine

import (
	"os"
	"strconv"
	"strings"
)

// A zombie (exited, not yet reaped) still has a /proc entry, so state Z and X
// count as gone, as does a missing entry or a different start time (PID reuse).
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

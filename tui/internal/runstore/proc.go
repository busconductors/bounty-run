package runstore

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PIDStart returns /proc/<pid>/stat field 22 (process start time in ticks).
// The comm field may contain spaces and parens, so parse after the LAST ')'.
func PIDStart(pid int) (int64, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, err
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 { // field 3 is f[0], so field 22 is f[19]
		return 0, fmt.Errorf("short stat for pid %d", pid)
	}
	return strconv.ParseInt(f[19], 10, 64)
}

// Alive reports whether pid exists and its start time equals pidStart
// (guards against PID reuse).
func Alive(pid int, pidStart int64) bool {
	if pid <= 0 {
		return false
	}
	got, err := PIDStart(pid)
	return err == nil && got == pidStart
}

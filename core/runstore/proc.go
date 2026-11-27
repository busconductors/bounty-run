package runstore

import (
	"strings"
	"time"
)

// Alive reports whether pid exists and its start time equals pidStart
// (guards against PID reuse). PIDStart is the per-OS source (see proc_*.go).
func Alive(pid int, pidStart int64) bool {
	if pid <= 0 {
		return false
	}
	got, err := PIDStart(pid)
	return err == nil && got == pidStart
}

// parseLstart parses a `ps -o lstart=` value ("Day Mon DD HH:MM:SS YYYY" in the
// C locale) to epoch seconds, read as UTC. Whitespace is normalised first
// because ps space-pads a single-digit day of month ("Nov  7"). The engine
// (runner/events.py:_parse_lstart) parses the same value the same way, so the
// two sides agree on macOS.
func parseLstart(s string) (int64, error) {
	norm := strings.Join(strings.Fields(s), " ")
	t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", norm, time.UTC)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

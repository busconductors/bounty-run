package runstore

import (
	"strings"
	"time"
)

// Alive (whether pid exists with start time == pidStart, guarding PID reuse) is
// per-OS: see proc_linux.go (/proc), proc_darwin.go (ps snapshot + fresh
// fallback), proc_other.go (stub). It lived here until the darwin liveness path
// needed a snapshot the linux path doesn't use.

// ParseLstart parses a `ps -o lstart=` value ("Day Mon DD HH:MM:SS YYYY" in the
// C locale) to epoch seconds, read as UTC. Whitespace is normalised first
// because ps space-pads a single-digit day of month ("Nov  7"). The engine
// (runner/events.py:_parse_lstart) parses the same value the same way, so the
// two sides agree on macOS. Exported so core/engine's darwin launch check
// reuses the one shared parser rather than reimplementing it.
func ParseLstart(s string) (int64, error) {
	norm := strings.Join(strings.Fields(s), " ")
	t, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", norm, time.UTC)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

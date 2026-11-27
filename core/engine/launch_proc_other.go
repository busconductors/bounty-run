//go:build !linux && !darwin

package engine

// procGone has no per-OS process source on unsupported platforms. It reports a
// valid pid as not-gone so WaitLaunch relies on the run_start event and the
// deadline instead of ever falsely reporting an exit. Exists only to compile.
func procGone(pid int, pidStart int64) bool {
	return pid <= 0
}

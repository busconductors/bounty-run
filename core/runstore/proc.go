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

// statFields returns the /proc/<pid>/stat fields after the comm field, so
// f[0] is field 3 (state), f[2] field 5 (pgrp) and f[19] field 22 (start).
func statFields(b []byte) []string {
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return nil
	}
	return strings.Fields(s[i+1:])
}

// GroupHasMemberSince reports whether some live process has process group
// pgid and a start time (stat field 22) >= since. A group whose members all
// predate since cannot belong to a run that started at since: its number has
// been reused by an unrelated job.
func GroupHasMemberSince(pgid int, since int64) bool {
	if pgid <= 0 {
		return false
	}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	want := strconv.Itoa(pgid)
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue // exited meanwhile
		}
		f := statFields(b)
		if len(f) < 20 || f[2] != want || f[0] == "Z" {
			continue
		}
		if st, err := strconv.ParseInt(f[19], 10, 64); err == nil && st >= since {
			return true
		}
	}
	return false
}

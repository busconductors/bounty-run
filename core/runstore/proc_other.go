//go:build !linux && !darwin

package runstore

import "errors"

// PIDStart has no start-time source on unsupported platforms; Alive then treats
// every pid as not-alive. These stubs exist only so the package compiles.
func PIDStart(pid int) (int64, error) {
	return 0, errors.New("runstore: PIDStart unsupported on this OS")
}

func GroupHasMemberSince(pgid int, since int64) bool {
	return false
}

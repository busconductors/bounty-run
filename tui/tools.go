//go:build tools

package tools

// Pins the chosen charm v2 family in go.mod until the UI packages import them.
import (
	_ "charm.land/bubbles/v2"
	_ "charm.land/huh/v2"
)

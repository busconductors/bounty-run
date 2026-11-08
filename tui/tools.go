//go:build tools

package tools

// Pins the chosen charm v2 family in go.mod until the UI packages import them.
import (
	_ "charm.land/bubbles/v2"
	_ "charm.land/bubbletea/v2"
	_ "charm.land/huh/v2"
	_ "charm.land/lipgloss/v2"
	_ "github.com/charmbracelet/x/exp/teatest/v2"
)

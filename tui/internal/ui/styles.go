// Package ui holds the bubbletea root model and screens.
package ui

import "charm.land/lipgloss/v2"

// Severity colours mirror runner/utils.py SEVERITY_COLOR
// (critical 31, high 38;5;208, medium 33, low 90, info 34).
var sevColor = map[string]string{
	"critical": "1",
	"high":     "208",
	"medium":   "3",
	"low":      "8",
	"info":     "4",
}

func sevStyle(sev string) lipgloss.Style {
	return lipgloss.NewStyle().Foreground(lipgloss.Color(sevColor[sev]))
}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	cursorStyle = lipgloss.NewStyle().Reverse(true)
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	runStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	badStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
)

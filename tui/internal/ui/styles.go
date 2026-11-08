// Package ui holds the bubbletea root model and screens.
package ui

import (
	"fmt"
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
)

// Palette. The base matches the HTML dashboard (runner/dashboard.py STYLESHEET:
// --bg, --panel, --border, --text, --muted); red is the brand accent.
var (
	colBase   = lipgloss.Color("#0d1117")
	colPanel  = lipgloss.Color("#161b22")
	colBorder = lipgloss.Color("#30363d")
	colText   = lipgloss.Color("#e6edf3")
	colMuted  = lipgloss.Color("#8b949e")
	colFaint  = lipgloss.Color("#6e7681")
	colRed    = lipgloss.Color("#f85149")
	colGreen  = lipgloss.Color("#3fb950")
	colAmber  = lipgloss.Color("#d29922")
)

// sevColor: critical/high red, medium amber, low/info dimmed.
var sevColor = map[string]color.Color{
	"critical": colRed,
	"high":     colRed,
	"medium":   colAmber,
	"low":      colFaint,
	"info":     colFaint,
}

func sevStyle(sev string) lipgloss.Style {
	s := lipgloss.NewStyle().Foreground(sevFg(sev))
	if sev == "critical" {
		s = s.Bold(true)
	}
	return s
}

func sevFg(sev string) color.Color {
	if c, ok := sevColor[sev]; ok {
		return c
	}
	return colMuted
}

// fgOnly colours s with a foreground-only SGR closed by 39 (default fg), not a
// full reset, so an enclosing style (the table's selected row) survives it.
func fgOnly(c color.Color, s string) string {
	r, g, b, _ := c.RGBA()
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[39m", r>>8, g>>8, b>>8, s)
}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Foreground(colText)
	dimStyle    = lipgloss.NewStyle().Foreground(colMuted)
	cursorStyle = lipgloss.NewStyle().Bold(true).Foreground(colText).Background(colPanel)
	okStyle     = lipgloss.NewStyle().Foreground(colGreen)
	runStyle    = lipgloss.NewStyle().Foreground(colAmber)
	badStyle    = lipgloss.NewStyle().Foreground(colRed)
	warnStyle   = lipgloss.NewStyle().Foreground(colAmber)
	greyStyle   = lipgloss.NewStyle().Foreground(colFaint)
	accentStyle = lipgloss.NewStyle().Foreground(colRed).Bold(true)
	keyStyle    = lipgloss.NewStyle().Foreground(colText).Bold(true)
	badgeStyle  = lipgloss.NewStyle().Bold(true).Foreground(colBase).Background(colRed).Padding(0, 1)
	bannerStyle = lipgloss.NewStyle().Foreground(colRed)
)

// paneBox is a rounded, padded box; focused panes get the red accent border.
func paneBox(focused bool) lipgloss.Style {
	c := colBorder
	if focused {
		c = colRed
	}
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(c).Padding(0, 1)
}

// headerBar is the one-line app header: a red badge, the screen title and
// optional dim context.
func headerBar(title, context string) string {
	h := badgeStyle.Render("BOUNTY RUN") + " " + titleStyle.Render(title)
	if context != "" {
		h += "  " + dimStyle.Render(context)
	}
	return h
}

// helpBar renders "key desc · key desc" with bold keys and muted descriptions.
// Each item is "key desc"; the first word is the key. The plain text is
// exactly the items joined by " · ".
func helpBar(items ...string) string {
	sep := greyStyle.Render(" · ")
	parts := make([]string, 0, len(items))
	for _, it := range items {
		k, d, _ := strings.Cut(it, " ")
		p := keyStyle.Render(k)
		if d != "" {
			p += " " + dimStyle.Render(d)
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, sep)
}

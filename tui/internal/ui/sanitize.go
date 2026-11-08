package ui

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// sanitize makes engine-supplied text (tool output, finding fields, stage ids,
// statuses) safe to print: it removes escape sequences and every C0 control
// except tab, DEL and C1 controls, so a hostile target cannot drive the
// user's terminal. Invalid UTF-8 becomes U+FFFD.
func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = ansi.Strip(s)
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return r
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return -1
		}
		return r
	}, s)
}

// oneLine sanitizes s for a single table cell (tabs become spaces).
func oneLine(s string) string { return strings.ReplaceAll(sanitize(s), "\t", " ") }

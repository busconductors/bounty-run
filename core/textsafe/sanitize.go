package textsafe

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// Sanitize makes engine-supplied text (tool output, finding fields, stage ids,
// statuses) safe to print: it removes escape sequences and every C0 control
// except tab, DEL, C1 controls and invisible format characters, so a hostile target cannot drive the
// user's terminal. Invalid UTF-8 becomes U+FFFD.
func Sanitize(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = ansi.Strip(s)
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t':
			return r
		case isFormat(r):
			return -1
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
			return -1
		}
		return r
	}, s)
}

// isFormat reports invisible format characters that can hide or spoof text:
// soft hyphen, Mongolian vowel separator, zero-width space/joiners, line and
// paragraph separators, word joiner and invisible operators, BOM, interlinear
// annotation controls and the tag block.
func isFormat(r rune) bool {
	switch {
	case r == 0xAD, r == 0x180E, r >= 0x200B && r <= 0x200D, r == 0x2028, r == 0x2029,
		r >= 0x2060 && r <= 0x2064, r == 0xFEFF, r >= 0xFFF9 && r <= 0xFFFB,
		r >= 0xE0000 && r <= 0xE007F:
		return true
	}
	return false
}

// OneLine sanitizes s for a single table cell (tabs become spaces).
func OneLine(s string) string { return strings.ReplaceAll(Sanitize(s), "\t", " ") }

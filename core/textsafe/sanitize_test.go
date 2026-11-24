package textsafe

import "testing"

func TestSanitizeStripsFormatCharacters(t *testing.T) {
	for _, r := range []rune{0xAD, 0x180E, 0x200B, 0x200C, 0x200D, 0x2028, 0x2029, 0x2060, 0x2064, 0xFEFF, 0xFFF9, 0xFFFB, 0xE0000, 0xE0041, 0xE007F} {
		if got := Sanitize("a" + string(r) + "b"); got != "ab" {
			t.Errorf("U+%04X survived: %q", r, got)
		}
	}
}

func TestSanitizeKeepsOrdinaryText(t *testing.T) {
	for _, in := range []string{"plain", "café \U0001F600", "a\tb", "中文"} {
		if got := Sanitize(in); got != in {
			t.Errorf("Sanitize(%q) = %q", in, got)
		}
	}
	if got := Sanitize("a\x1b[31mb\x00c\u0085"); got != "abc" {
		t.Errorf("controls: %q", got)
	}
}

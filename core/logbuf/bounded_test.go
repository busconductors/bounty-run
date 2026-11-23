package logbuf

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func totalBytes(b *Bounded) int {
	n := 0
	for _, l := range b.Lines() {
		n += len(l)
	}
	return n
}

func TestBoundedEvictsByLines(t *testing.T) {
	b := NewBounded(3, 1000)
	for _, s := range []string{"a", "b", "c", "d", "e"} {
		b.Push(s)
	}
	got := strings.Join(b.Lines(), ",")
	if got != "c,d,e" || b.Dropped() != 2 {
		t.Fatalf("lines=%s dropped=%d", got, b.Dropped())
	}
}

func TestBoundedEvictsByBytes(t *testing.T) {
	b := NewBounded(100, 10)
	b.Push("aaaa")
	b.Push("bbbb")
	b.Push("cccc")
	if got := strings.Join(b.Lines(), ","); got != "bbbb,cccc" {
		t.Fatalf("lines=%s", got)
	}
	if b.Dropped() != 1 || totalBytes(b) > 10 {
		t.Fatalf("dropped=%d bytes=%d", b.Dropped(), totalBytes(b))
	}
}

func TestBoundedOversizeLine(t *testing.T) {
	b := NewBounded(10, 32)
	b.Push(strings.Repeat("é", 1000)) // multibyte: must cut on a rune boundary
	ls := b.Lines()
	if len(ls) != 1 {
		t.Fatalf("lines=%d", len(ls))
	}
	if len(ls[0]) > 32 || !utf8.ValidString(ls[0]) || !strings.HasSuffix(ls[0], truncMarker) {
		t.Fatalf("bad stored line %q (%d bytes)", ls[0], len(ls[0]))
	}
}

func TestBoundedTinyLimitStillFits(t *testing.T) {
	b := NewBounded(10, 3) // smaller than the marker
	b.Push(strings.Repeat("x", 100))
	for _, l := range b.Lines() {
		if len(l) > 3 || !utf8.ValidString(l) {
			t.Fatalf("bad %q", l)
		}
	}
}

func TestBoundedNonPositiveLimits(t *testing.T) {
	for _, c := range [][2]int{{0, 100}, {-1, 100}, {5, 0}, {5, -3}, {0, 0}} {
		b := NewBounded(c[0], c[1])
		for i := 0; i < 100; i++ {
			b.Push("line")
		}
		if len(b.Lines()) != 0 || b.Dropped() != 100 {
			t.Fatalf("%v: lines=%d dropped=%d", c, len(b.Lines()), b.Dropped())
		}
	}
}

func TestBoundedHostileInputStaysBounded(t *testing.T) {
	b := NewBounded(50, 200)
	for i := 0; i < 10000; i++ {
		b.Push(strings.Repeat("\xff", i%500)) // invalid UTF-8 too
		if totalBytes(b) > 200 || len(b.Lines()) > 50 {
			t.Fatalf("limit exceeded at %d", i)
		}
	}
}

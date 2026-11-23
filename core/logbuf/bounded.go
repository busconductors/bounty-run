package logbuf

import (
	"strings"
	"unicode/utf8"
)

const truncMarker = "[truncated]"

// Bounded keeps the most recent lines of output within both a line-count and
// a byte limit. The stored bytes (including truncation markers) never exceed
// maxBytes. If either limit is not positive, nothing is stored and every
// pushed line counts as dropped.
type Bounded struct {
	maxLines, maxBytes int
	lines              []string
	head               int // index of the oldest live line in lines
	bytes              int
	dropped            int
}

// NewBounded returns a buffer holding at most maxLines lines and maxBytes bytes.
func NewBounded(maxLines, maxBytes int) *Bounded {
	return &Bounded{maxLines: maxLines, maxBytes: maxBytes}
}

// Push appends a line, evicting the oldest lines until both limits hold. A
// line longer than maxBytes is truncated on a UTF-8 boundary and marked.
func (b *Bounded) Push(s string) {
	if b.maxLines <= 0 || b.maxBytes <= 0 {
		b.dropped++
		return
	}
	if len(s) > b.maxBytes {
		s = truncate(s, b.maxBytes)
	} else {
		s = strings.Clone(s) // do not pin the caller's backing array
	}
	for b.live() > 0 && (b.live() >= b.maxLines || b.bytes+len(s) > b.maxBytes) {
		b.evict()
	}
	b.lines = append(b.lines, s)
	b.bytes += len(s)
}

// Lines returns the buffered lines, oldest first.
func (b *Bounded) Lines() []string {
	return append([]string(nil), b.lines[b.head:]...)
}

// Dropped returns how many lines were evicted (or rejected) so far.
func (b *Bounded) Dropped() int { return b.dropped }

func (b *Bounded) live() int { return len(b.lines) - b.head }

func (b *Bounded) evict() {
	b.bytes -= len(b.lines[b.head])
	b.lines[b.head] = "" // release the string
	b.head++
	b.dropped++
	if b.head > 64 && b.head*2 >= len(b.lines) { // compact so the array stays small
		n := copy(b.lines, b.lines[b.head:])
		clear(b.lines[n:])
		b.lines = b.lines[:n]
		b.head = 0
	}
}

// truncate returns a fresh string of at most limit bytes ending in the marker
// (or a prefix of it when limit is smaller than the marker), cut on a rune
// boundary. limit must be positive and less than len(s).
func truncate(s string, limit int) string {
	if limit <= len(truncMarker) {
		return truncMarker[:limit]
	}
	i := limit - len(truncMarker)
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return strings.Clone(s[:i]) + truncMarker
}

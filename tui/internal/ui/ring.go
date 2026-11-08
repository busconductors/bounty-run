package ui

const ringCap = 5000

// ring keeps the most recent ringCap lines of tool output.
type ring struct {
	buf   [ringCap]string
	start int // index of the oldest line
	n     int
}

// Push appends a line, evicting the oldest when full.
func (r *ring) Push(s string) {
	if r.n < ringCap {
		r.buf[(r.start+r.n)%ringCap] = s
		r.n++
		return
	}
	r.buf[r.start] = s
	r.start = (r.start + 1) % ringCap
}

// Lines returns the buffered lines, oldest first.
func (r *ring) Lines() []string {
	out := make([]string, r.n)
	for i := range r.n {
		out[i] = r.buf[(r.start+i)%ringCap]
	}
	return out
}

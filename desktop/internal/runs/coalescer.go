package runs

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/busconductors/bounty-run/core/events"
	"github.com/busconductors/bounty-run/core/logbuf"
	"github.com/busconductors/bounty-run/core/textsafe"
)

// Coalescer limits. A batch is flushed every FlushInterval, or as soon as
// FlushEvents non-output events are pending. Output lines are buffered in a
// logbuf.Bounded(outputBufLines, outputBufBytes) between flushes and at most
// the MaxOutputPerFlush most recent ones are sent; the rest are counted in
// Batch.Elided. Display lines are cut to MaxLineBytes.
const (
	FlushInterval     = 75 * time.Millisecond
	FlushEvents       = 1000
	FlushBytes        = 4 << 20
	MaxOutputPerFlush = 2000
	MaxLineBytes      = 64 << 10
	outputBufLines    = 5000
	outputBufBytes    = 8 << 20
)

const truncMarker = "…[truncated]"

// Batch is the payload of run:<id>:batch. Events are the structural events in
// engine order, in the events v1 wire shape, with progress collapsed to the
// latest per stage. Output holds sanitized tool output. Elided counts output
// lines dropped since the previous batch. Reset means the event stream was
// replaced: the client discards what it derived from earlier batches before
// applying this one.
type Batch struct {
	Events []map[string]any `json:"events"`
	Output []OutputLine     `json:"output"`
	Elided int              `json:"elided"`
	Reset  bool             `json:"reset"`
}

// OutputLine is one sanitized line of tool output.
type OutputLine struct {
	T      int64  `json:"t"`
	Stage  string `json:"stage"`
	Tool   string `json:"tool"`
	Stream string `json:"stream"`
	Line   string `json:"line"`
}

// Clock is the time source for the run loops; tests substitute a fake.
type Clock interface {
	NewTicker(d time.Duration) Ticker
}

// Ticker is the part of time.Ticker the loops use.
type Ticker interface {
	C() <-chan time.Time
	Stop()
}

type realClock struct{}

type realTicker struct{ t *time.Ticker }

func (realClock) NewTicker(d time.Duration) Ticker { return realTicker{time.NewTicker(d)} }
func (r realTicker) C() <-chan time.Time           { return r.t.C }
func (r realTicker) Stop()                         { r.t.Stop() }

// coalescer accumulates tail messages between flushes.
type coalescer struct {
	events   []map[string]any
	sizes    []int          // approximate wire size of each entry in events
	bytes    int            // sum of sizes
	progress map[string]int // stage -> index of its progress event in events
	out      *logbuf.Bounded
	nOut     int // lines pushed into out since the last flush
	reset    bool
}

func newCoalescer() *coalescer {
	return &coalescer{progress: map[string]int{}, out: logbuf.NewBounded(outputBufLines, outputBufBytes)}
}

func (c *coalescer) push(w map[string]any, size int) {
	c.events = append(c.events, w)
	c.sizes = append(c.sizes, size)
	c.bytes += size
}

// add applies one message from events.Tail and reports whether enough events
// (FlushEvents) or bytes of them (FlushBytes) are pending to flush now.
func (c *coalescer) add(m any) bool {
	switch m := m.(type) {
	case events.Msg:
		ev := m.Ev
		switch ev.Type {
		case "output":
			c.out.Push(encodeOutput(ev))
			c.nOut++
		case "progress":
			w, size := wireEvent(ev)
			if i, ok := c.progress[ev.Stage]; ok {
				c.events[i] = w // keep only the latest count per stage
				c.bytes += size - c.sizes[i]
				c.sizes[i] = size
			} else {
				c.progress[ev.Stage] = len(c.events)
				c.push(w, size)
			}
		default:
			c.push(wireEvent(ev))
		}
	case events.WarnMsg:
		msg := display(m.Text)
		c.push(map[string]any{"v": 1, "type": "log", "level": "warn", "msg": msg}, len(msg)+64)
	case events.VersionMsg:
		c.push(map[string]any{"v": 1, "type": "log", "level": "error",
			"msg": "this run was written by an incompatible engine version; it cannot be shown"}, 128)
	case events.ResetMsg:
		*c = *newCoalescer()
		c.reset = true
	}
	return len(c.events) >= FlushEvents || c.bytes >= FlushBytes
}

func (c *coalescer) pending() bool { return c.reset || len(c.events) > 0 || c.nOut > 0 }

// flush returns the pending batch and starts a new one.
func (c *coalescer) flush() Batch {
	lines := c.out.Lines()
	elided := c.nOut - len(lines) // evicted by the buffer's own bounds
	if len(lines) > MaxOutputPerFlush {
		elided += len(lines) - MaxOutputPerFlush
		lines = lines[len(lines)-MaxOutputPerFlush:]
	}
	b := Batch{Events: c.events, Output: make([]OutputLine, len(lines)), Elided: elided, Reset: c.reset}
	if b.Events == nil {
		b.Events = []map[string]any{}
	}
	for i, l := range lines {
		b.Output[i] = decodeOutput(l)
	}
	*c = *newCoalescer()
	return b
}

// pump feeds messages from in through a coalescer and emits a batch whenever
// FlushEvents events or FlushBytes of them are pending, or flushC ticks with
// anything pending. Without lv it returns when ctx is done or in is closed.
// With lv it also watches the engine and reports it dead exactly once, after
// the final batch: once the process is gone and the tail has consumed the
// whole events file (an events.EOFMsg at or past its final size), or the tail
// has stopped. It then runs until ctx is done.
func pump(ctx context.Context, in <-chan any, flushC <-chan time.Time, emit func(Batch), lv *liveness) {
	c := newCoalescer()
	var liveC <-chan time.Time
	if lv != nil {
		liveC = lv.c
	}
	var (
		gone      bool  // the engine process has ended
		finalSize int64 // events file size seen after it ended; -1: no file
		consumed  int64 = -1
		tailEnded bool
		reported  bool
	)
	maybeDead := func() {
		if reported || !gone || !(tailEnded || finalSize < 0 || consumed >= finalSize) {
			return
		}
		if c.pending() {
			emit(c.flush())
		}
		lv.report()
		reported = true
	}
	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-in:
			if !ok {
				if c.pending() {
					emit(c.flush())
				}
				if lv == nil {
					return
				}
				in, tailEnded = nil, true
				maybeDead()
				continue
			}
			switch m := m.(type) {
			case events.EOFMsg:
				consumed = m.Offset
				if lv != nil {
					maybeDead()
				}
				continue
			case events.ResetMsg:
				consumed = -1
			}
			if c.add(m) {
				emit(c.flush())
			}
		case <-flushC:
			if c.pending() {
				emit(c.flush())
			}
		case <-liveC:
			if lv.alive() {
				continue
			}
			// The process is gone, so the file has its final size: dead is
			// reported once the tail has read up to it.
			gone, liveC = true, nil
			if size, ok := lv.size(); ok {
				finalSize = size
			} else {
				finalSize = -1
			}
			maybeDead()
		}
	}
}

// liveness polls the engine on c. alive reports whether the engine process
// still runs; size returns the events file's size (false if it is missing);
// report announces the engine dead.
type liveness struct {
	c      <-chan time.Time
	alive  func() bool
	size   func() (int64, bool)
	report func()
}

// wireEvent converts a decoded event back to the events v1 wire shape, so the
// client sees the contract's field names. Zero-valued fields are omitted,
// except progress counts, which are meaningful at zero.
func wireEvent(ev events.Event) (map[string]any, int) {
	w := map[string]any{"v": ev.V, "t": ev.T, "type": ev.Type}
	size := 64
	str := func(k, v string) {
		if v != "" {
			v = clip(v)
			w[k] = v
			size += len(k) + len(v) + 8
		}
	}
	str("target", ev.Target)
	str("stage", ev.Stage)
	str("status", ev.Status)
	str("reason", ev.Reason)
	str("level", ev.Level)
	str("msg", ev.Msg)
	str("tool", ev.Tool)
	str("stream", ev.Stream)
	str("line", ev.Line)
	str("severity", ev.Severity)
	str("template", ev.Template)
	str("host", ev.Host)
	str("url", ev.URL)
	str("report", ev.Report)
	str("error", ev.Error)
	if ev.Type == "run_end" {
		str("summary", ev.SummaryPath)
	} else {
		str("summary", ev.Summary)
	}
	if ev.Stages != nil {
		stages := make([]string, len(ev.Stages))
		for i, st := range ev.Stages {
			stages[i] = clip(st)
			size += len(stages[i]) + 4
		}
		w["stages"] = stages
	}
	if ev.Flags != nil {
		w["flags"] = ev.Flags
		size += approxSize(ev.Flags)
	}
	for k, m := range map[string]map[string]int{"counts": ev.Counts, "totals": ev.Totals} {
		if m != nil {
			w[k] = m
			for name := range m {
				size += len(name) + 24
			}
		}
	}
	if ev.DurationMs != 0 {
		w["duration_ms"] = ev.DurationMs
	}
	if ev.Type == "progress" {
		w["done"], w["total"] = ev.Done, ev.Total
	}
	return w, size
}

// approxSize estimates the JSON size of a decoded value (run_start flags).
func approxSize(v any) int {
	switch v := v.(type) {
	case string:
		return len(v) + 8
	case map[string]any:
		n := 8
		for k, e := range v {
			n += len(k) + 8 + approxSize(e)
		}
		return n
	case []any:
		n := 8
		for _, e := range v {
			n += approxSize(e) + 2
		}
		return n
	default:
		return 24
	}
}

// Output lines are held in the Bounded buffer as one string so its byte
// accounting covers every field. Sanitized text never contains NUL, so it
// separates the fields safely.
const sep = "\x00"

func encodeOutput(ev events.Event) string {
	return strings.Join([]string{
		strconv.FormatInt(ev.T, 10),
		display(ev.Stage), display(ev.Tool), display(ev.Stream), display(ev.Line),
	}, sep)
}

func decodeOutput(s string) OutputLine {
	f := strings.SplitN(s, sep, 5)
	for len(f) < 5 {
		f = append(f, "")
	}
	t, _ := strconv.ParseInt(f[0], 10, 64)
	return OutputLine{T: t, Stage: f[1], Tool: f[2], Stream: f[3], Line: f[4]}
}

// clip cuts a structural event field to MaxLineBytes on a rune boundary,
// ending it with truncMarker. Fields are not sanitized: the client renders
// them as text.
func clip(s string) string {
	if len(s) <= MaxLineBytes {
		return s
	}
	i := MaxLineBytes - len(truncMarker)
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + truncMarker
}

// display sanitizes engine-supplied text for display and cuts it to
// MaxLineBytes on a rune boundary, ending a cut line with truncMarker.
func display(s string) string {
	cut := len(s) > 4*MaxLineBytes
	if cut { // bound the sanitizer's work on huge lines
		s = s[:4*MaxLineBytes]
	}
	s = textsafe.Sanitize(s)
	if !cut && len(s) <= MaxLineBytes {
		return s
	}
	i := min(len(s), MaxLineBytes-len(truncMarker))
	for i > 0 && i < len(s) && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i] + truncMarker
}

package runs

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"bountyrun/core/events"
	"bountyrun/core/logbuf"
	"bountyrun/core/textsafe"
)

// Coalescer limits. A batch is flushed every FlushInterval, or as soon as
// FlushEvents non-output events are pending. Output lines are buffered in a
// logbuf.Bounded(outputBufLines, outputBufBytes) between flushes and at most
// the MaxOutputPerFlush most recent ones are sent; the rest are counted in
// Batch.Elided. Display lines are cut to MaxLineBytes.
const (
	FlushInterval     = 75 * time.Millisecond
	FlushEvents       = 1000
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
	progress map[string]int // stage -> index of its progress event in events
	out      *logbuf.Bounded
	nOut     int // lines pushed into out since the last flush
	reset    bool
}

func newCoalescer() *coalescer {
	return &coalescer{progress: map[string]int{}, out: logbuf.NewBounded(outputBufLines, outputBufBytes)}
}

// add applies one message from events.Tail and reports whether enough events
// are pending to flush now.
func (c *coalescer) add(m any) bool {
	switch m := m.(type) {
	case events.Msg:
		ev := m.Ev
		switch ev.Type {
		case "output":
			c.out.Push(encodeOutput(ev))
			c.nOut++
		case "progress":
			w := wireEvent(ev)
			if i, ok := c.progress[ev.Stage]; ok {
				c.events[i] = w // keep only the latest count per stage
			} else {
				c.progress[ev.Stage] = len(c.events)
				c.events = append(c.events, w)
			}
		default:
			c.events = append(c.events, wireEvent(ev))
		}
	case events.WarnMsg:
		c.events = append(c.events, map[string]any{"v": 1, "type": "log", "level": "warn", "msg": display(m.Text)})
	case events.VersionMsg:
		c.events = append(c.events, map[string]any{"v": 1, "type": "log", "level": "error",
			"msg": "this run was written by an incompatible engine version; it cannot be shown"})
	case events.ResetMsg:
		*c = *newCoalescer()
		c.reset = true
	}
	return len(c.events) >= FlushEvents
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
// FlushEvents events are pending or flushC ticks with anything pending. It
// returns when ctx is done or in is closed. lv, when set, watches the engine.
func pump(ctx context.Context, in <-chan any, flushC <-chan time.Time, emit func(Batch), lv *liveness) {
	c := newCoalescer()
	var liveC <-chan time.Time
	if lv != nil {
		liveC = lv.c
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
				return
			}
			if c.add(m) {
				emit(c.flush())
			}
		case <-flushC:
			if c.pending() {
				emit(c.flush())
			}
		case <-liveC:
			// The engine is reported dead on the second consecutive tick
			// that finds it gone, so the tail has read its last lines; the
			// final batch goes out before the dead notice.
			if lv.check() {
				if c.pending() {
					emit(c.flush())
				}
				lv.report()
				liveC = nil
			}
		}
	}
}

// liveness polls the engine on c; check reports when it is confirmed dead.
type liveness struct {
	c       <-chan time.Time
	alive   func() bool
	report  func()
	missing int
}

func (l *liveness) check() bool {
	if l.alive() {
		l.missing = 0
		return false
	}
	l.missing++
	return l.missing >= 2
}

// wireEvent converts a decoded event back to the events v1 wire shape, so the
// client sees the contract's field names. Zero-valued fields are omitted,
// except progress counts, which are meaningful at zero.
func wireEvent(ev events.Event) map[string]any {
	w := map[string]any{"v": ev.V, "t": ev.T, "type": ev.Type}
	str := func(k, v string) {
		if v != "" {
			w[k] = v
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
		w["stages"] = ev.Stages
	}
	if ev.Flags != nil {
		w["flags"] = ev.Flags
	}
	if ev.Counts != nil {
		w["counts"] = ev.Counts
	}
	if ev.Totals != nil {
		w["totals"] = ev.Totals
	}
	if ev.DurationMs != 0 {
		w["duration_ms"] = ev.DurationMs
	}
	if ev.Type == "progress" {
		w["done"], w["total"] = ev.Done, ev.Total
	}
	return w
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

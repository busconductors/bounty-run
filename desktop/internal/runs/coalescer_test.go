package runs

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"bountyrun/core/events"
)

// pumpHarness drives pump with a fake clock. in is unbuffered, so once a send
// returns the pump has taken the message and will apply it before it reads
// the next tick.
type pumpHarness struct {
	t     *testing.T
	clk   *fakeClock
	in    chan any
	out   chan Batch
	stop  context.CancelFunc
	ended chan struct{}
}

func newPump(t *testing.T) *pumpHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &pumpHarness{t: t, clk: newFakeClock(), in: make(chan any), out: make(chan Batch, 1024), stop: cancel, ended: make(chan struct{})}
	flush := h.clk.NewTicker(FlushInterval)
	go func() {
		defer close(h.ended)
		pump(ctx, h.in, flush.C(), func(b Batch) { h.out <- b }, nil)
	}()
	t.Cleanup(func() { cancel(); <-h.ended; flush.Stop() })
	return h
}

func (h *pumpHarness) send(m any) { h.in <- m }

func (h *pumpHarness) ev(e events.Event) {
	e.V = 1
	h.send(events.Msg{RunDir: "/x", Ev: e})
}

func (h *pumpHarness) output(line string) {
	h.ev(events.Event{Type: "output", Stage: "s", Tool: "tool", Stream: "stdout", Line: line})
}

// tick advances past one flush interval and returns the batch it produced.
func (h *pumpHarness) tick() Batch {
	h.t.Helper()
	h.clk.Advance(FlushInterval)
	return h.next()
}

func (h *pumpHarness) next() Batch {
	h.t.Helper()
	select {
	case b := <-h.out:
		return b
	case <-time.After(5 * time.Second):
		h.t.Fatal("no batch emitted")
		return Batch{}
	}
}

// drain collects batches until none arrives for a moment.
func (h *pumpHarness) drain() []Batch {
	var bs []Batch
	for {
		select {
		case b := <-h.out:
			bs = append(bs, b)
		case <-time.After(100 * time.Millisecond):
			return bs
		}
	}
}

func TestStructuralEventsNeverDropped(t *testing.T) {
	h := newPump(t)
	const findings = 5000
	h.ev(events.Event{Type: "stage_start", Stage: "s"})
	for i := range findings {
		h.ev(events.Event{Type: "finding", Severity: "high", Template: fmt.Sprintf("f%d", i)})
		for range 4 { // heavy output interleaved: must not crowd findings out
			h.output("noise")
		}
	}
	h.ev(events.Event{Type: "stage_end", Stage: "s", Status: "ok"})
	h.ev(events.Event{Type: "run_end", Status: "ok"})

	bs := h.drain() // count-triggered flushes, no clock needed
	bs = append(bs, h.tick())
	var got []string
	for _, b := range bs {
		if len(b.Events) > FlushEvents {
			t.Fatalf("batch carries %d events, over the %d flush threshold", len(b.Events), FlushEvents)
		}
		for _, ev := range b.Events {
			if ev["type"] == "finding" {
				got = append(got, ev["template"].(string))
			}
		}
	}
	if len(got) != findings {
		t.Fatalf("got %d findings, want %d", len(got), findings)
	}
	for i, tmpl := range got {
		if tmpl != fmt.Sprintf("f%d", i) {
			t.Fatalf("finding %d is %q: order not preserved", i, tmpl)
		}
	}
	types := eventTypes(bs)
	if types[0] != "stage_start" || types[len(types)-1] != "run_end" {
		t.Fatalf("structural events missing or reordered: first %q last %q", types[0], types[len(types)-1])
	}
}

func TestCountTriggeredFlushWithoutClock(t *testing.T) {
	h := newPump(t)
	for range FlushEvents {
		h.ev(events.Event{Type: "log", Level: "info", Msg: "m"})
	}
	b := h.next() // no Advance: the 1000th event flushes on its own
	if len(b.Events) != FlushEvents {
		t.Fatalf("got %d events, want %d", len(b.Events), FlushEvents)
	}
}

func TestProgressCollapsedPerStage(t *testing.T) {
	h := newPump(t)
	h.ev(events.Event{Type: "stage_start", Stage: "a"})
	for i := 1; i <= 300; i++ {
		h.ev(events.Event{Type: "progress", Stage: "a", Done: i, Total: 300})
		if i <= 120 {
			h.ev(events.Event{Type: "progress", Stage: "b", Done: i, Total: 120})
		}
	}
	h.ev(events.Event{Type: "finding", Severity: "low"})
	b := h.tick()
	var progress []map[string]any
	for _, ev := range b.Events {
		if ev["type"] == "progress" {
			progress = append(progress, ev)
		}
	}
	if len(progress) != 2 {
		t.Fatalf("got %d progress events, want one per stage: %v", len(progress), progress)
	}
	last := map[string]int{}
	for _, p := range progress {
		last[p["stage"].(string)] = p["done"].(int)
	}
	if last["a"] != 300 || last["b"] != 120 {
		t.Fatalf("progress not the latest per stage: %v", last)
	}
	if types := eventTypes([]Batch{b}); types[0] != "stage_start" || types[len(types)-1] != "finding" {
		t.Fatalf("unexpected order %v", types)
	}
	// A zero done count is real data and must reach the client.
	h.ev(events.Event{Type: "progress", Stage: "c", Done: 0, Total: 5})
	b = h.tick()
	if v, ok := b.Events[0]["done"]; !ok || v.(int) != 0 {
		t.Fatalf("progress done=0 dropped from wire event: %v", b.Events[0])
	}
}

func TestOutputElidedCounted(t *testing.T) {
	h := newPump(t)
	const n = 6000
	for i := range n {
		h.output(fmt.Sprintf("line %d", i))
	}
	b := h.tick()
	if len(b.Output) != MaxOutputPerFlush {
		t.Fatalf("got %d output lines, want %d", len(b.Output), MaxOutputPerFlush)
	}
	if b.Elided != n-MaxOutputPerFlush {
		t.Fatalf("elided = %d, want %d", b.Elided, n-MaxOutputPerFlush)
	}
	if first, last := b.Output[0].Line, b.Output[len(b.Output)-1].Line; first != fmt.Sprintf("line %d", n-MaxOutputPerFlush) || last != fmt.Sprintf("line %d", n-1) {
		t.Fatalf("kept %q..%q, want the most recent lines", first, last)
	}
	// The next flush starts from zero.
	h.output("after")
	b = h.tick()
	if len(b.Output) != 1 || b.Elided != 0 {
		t.Fatalf("second flush: %d lines, elided %d", len(b.Output), b.Elided)
	}
}

func TestOversizeLineTruncated(t *testing.T) {
	h := newPump(t)
	long := strings.Repeat("é", 100<<10) // 200 KiB of 2-byte runes
	h.output(long)
	b := h.tick()
	got := b.Output[0].Line
	if len(got) > MaxLineBytes {
		t.Fatalf("line is %d bytes, over %d", len(got), MaxLineBytes)
	}
	if !strings.HasSuffix(got, truncMarker) {
		t.Fatalf("truncated line lacks marker: ...%q", got[len(got)-20:])
	}
	if !utf8.ValidString(got) {
		t.Fatal("truncation split a rune")
	}
}

func TestOutputSanitized(t *testing.T) {
	h := newPump(t)
	h.ev(events.Event{Type: "output", Stage: "s\x1b[2J", Tool: "to\x07ol", Stream: "stdout",
		Line: "\x1b[31mred\x1b[0m\x07 \x1b]0;title\x07ok\r\x00\xff"})
	b := h.tick()
	o := b.Output[0]
	if o.Line != "red ok�" {
		t.Fatalf("line = %q", o.Line)
	}
	if o.Tool != "tool" || o.Stage != "s" {
		t.Fatalf("tool/stage not sanitized: %q %q", o.Tool, o.Stage)
	}
}

func TestResetClearsPendingAndFlags(t *testing.T) {
	h := newPump(t)
	h.ev(events.Event{Type: "run_start"})
	h.output("old")
	h.send(events.ResetMsg{})
	h.ev(events.Event{Type: "run_start", Target: "new"})
	b := h.tick()
	if !b.Reset || len(b.Events) != 1 || b.Events[0]["target"] != "new" || len(b.Output) != 0 {
		t.Fatalf("reset batch = %+v", b)
	}
	h.send(events.ResetMsg{}) // an empty reset still reaches the client
	if b = h.tick(); !b.Reset {
		t.Fatal("bare reset not flushed")
	}
}

func TestWarningsBecomeLogEvents(t *testing.T) {
	h := newPump(t)
	h.send(events.WarnMsg{RunDir: "/x", Text: "skipped \x1b[31mbad\x1b[0m line"})
	h.send(events.VersionMsg{RunDir: "/x"})
	b := h.tick()
	if len(b.Events) != 2 || b.Events[0]["level"] != "warn" || b.Events[0]["msg"] != "skipped bad line" || b.Events[1]["level"] != "error" {
		t.Fatalf("events = %v", b.Events)
	}
}

func TestNoEmptyFlush(t *testing.T) {
	h := newPump(t)
	h.clk.Advance(10 * FlushInterval)
	select {
	case b := <-h.out:
		t.Fatalf("empty batch emitted: %+v", b)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestStructuralBytesBoundFlush(t *testing.T) {
	h := newPump(t)
	big := strings.Repeat("s", 300<<10)
	const n = 200
	for i := range n {
		h.ev(events.Event{Type: "finding", Severity: "high", Template: fmt.Sprint(i), Summary: big, URL: big, Host: big})
	}
	bs := h.drain() // no tick: the byte threshold alone must flush
	if len(bs) == 0 {
		t.Fatal("no byte-triggered flush")
	}
	bs = append(bs, h.tick())
	got := 0
	for _, b := range bs {
		size := 0
		for _, ev := range b.Events {
			got++
			for _, k := range []string{"summary", "url", "host"} {
				l := len(ev[k].(string))
				if l > MaxLineBytes {
					t.Fatalf("%s is %d bytes, over %d", k, l, MaxLineBytes)
				}
				size += l
			}
		}
		if size > FlushBytes+3*MaxLineBytes {
			t.Fatalf("batch holds %d bytes of strings, over %d", size, FlushBytes)
		}
	}
	if got != n {
		t.Fatalf("got %d findings, want %d", got, n)
	}
}

// deadHarness runs pump with a liveness check that always finds the engine
// gone and an events file of finalSize bytes.
func deadHarness(t *testing.T, finalSize int64, exists bool) (h *pumpHarness, live Ticker, dead chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h = &pumpHarness{t: t, clk: newFakeClock(), in: make(chan any), out: make(chan Batch, 1024), stop: cancel, ended: make(chan struct{})}
	flush := h.clk.NewTicker(FlushInterval)
	live = h.clk.NewTicker(time.Second)
	dead = make(chan struct{}, 4)
	lv := &liveness{
		c:      live.C(),
		alive:  func() bool { return false },
		size:   func() (int64, bool) { return finalSize, exists },
		report: func() { dead <- struct{}{} },
	}
	go func() {
		defer close(h.ended)
		pump(ctx, h.in, flush.C(), func(b Batch) { h.out <- b }, lv)
	}()
	t.Cleanup(func() { cancel(); <-h.ended })
	return h, live, dead
}

func expectDead(t *testing.T, dead chan struct{}, want bool) {
	t.Helper()
	select {
	case <-dead:
		if !want {
			t.Fatal("dead reported before the tail drained the file")
		}
	case <-time.After(150 * time.Millisecond):
		if want {
			t.Fatal("dead not reported")
		}
	}
}

func TestDeadWaitsForTailToDrain(t *testing.T) {
	h, _, dead := deadHarness(t, 1000, true)
	h.send(events.EOFMsg{Offset: 400}) // caught up with a file still growing
	h.clk.Advance(time.Second)         // engine found gone; 600 bytes unread
	expectDead(t, dead, false)
	h.clk.Advance(5 * time.Second)
	expectDead(t, dead, false)
	h.ev(events.Event{Type: "run_end", Status: "ok"})
	h.send(events.EOFMsg{Offset: 1000})
	b := h.next() // the final batch is flushed before dead
	if len(b.Events) != 1 || b.Events[0]["type"] != "run_end" {
		t.Fatalf("final batch = %+v", b)
	}
	expectDead(t, dead, true)
	h.send(events.EOFMsg{Offset: 1000})
	h.clk.Advance(time.Second)
	expectDead(t, dead, false) // once only
}

func TestDeadWithoutEventsFile(t *testing.T) {
	h, _, dead := deadHarness(t, 0, false)
	h.clk.Advance(time.Second)
	expectDead(t, dead, true)
}

func TestDeadAfterTailEnds(t *testing.T) {
	h, _, dead := deadHarness(t, 1000, true)
	h.send(events.VersionMsg{RunDir: "/x"}) // Tail stops after this
	close(h.in)
	h.clk.Advance(time.Second)
	expectDead(t, dead, true)
}

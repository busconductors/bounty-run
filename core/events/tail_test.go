package events

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const deadline = 5 * time.Second

func startTail(t *testing.T, path string) <-chan any {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan any, 16)
	go Tail(ctx, path, out)
	return out
}

func next(t *testing.T, ch <-chan any) any {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(deadline):
		t.Fatal("timed out waiting for msg")
		return nil
	}
}

func expectNone(t *testing.T, ch <-chan any, d time.Duration) {
	t.Helper()
	select {
	case m := <-ch:
		t.Fatalf("unexpected msg: %#v", m)
	case <-time.After(d):
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func logLine(msg string) string {
	return `{"v":1,"t":1,"type":"log","level":"info","msg":"` + msg + `"}` + "\n"
}

func wantMsg(t *testing.T, m any, text string) {
	t.Helper()
	got, ok := m.(Msg)
	if !ok {
		t.Fatalf("want Msg, got %#v", m)
	}
	if got.Ev.Msg != text {
		t.Fatalf("msg = %q, want %q", got.Ev.Msg, text)
	}
}

func TestTailReplayThenFollow(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("a")+logLine("b")+logLine("c"))
	ch := startTail(t, p)
	for _, s := range []string{"a", "b", "c"} {
		wantMsg(t, next(t, ch), s)
	}
	appendFile(t, p, logLine("d")+logLine("e"))
	wantMsg(t, next(t, ch), "d")
	wantMsg(t, next(t, ch), "e")
}

func TestTailMissingFileAppears(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	ch := startTail(t, p)
	expectNone(t, ch, 300*time.Millisecond)
	appendFile(t, p, logLine("late"))
	wantMsg(t, next(t, ch), "late")
}

func TestTailPartialLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, `{"v":1,"t":1,"type":"lo`)
	ch := startTail(t, p)
	expectNone(t, ch, 300*time.Millisecond)
	appendFile(t, p, `g","level":"info","msg":"x"}`+"\n")
	wantMsg(t, next(t, ch), "x")
	expectNone(t, ch, 300*time.Millisecond)
}

func TestTailLongLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	big := strings.Repeat("A", 1<<20)
	appendFile(t, p, `{"v":1,"t":1,"type":"output","stage":"s","tool":"t","stream":"stdout","line":"`+big+`"}`+"\n")
	ch := startTail(t, p)
	m, ok := next(t, ch).(Msg)
	if !ok || m.Ev.Line != big {
		t.Fatalf("long line not intact: ok=%v len=%d", ok, len(m.Ev.Line))
	}
}

func TestTailCorruptLineWarns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("a")+"garbage\n"+logLine("b"))
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "a")
	if _, ok := next(t, ch).(WarnMsg); !ok {
		t.Fatal("want WarnMsg")
	}
	wantMsg(t, next(t, ch), "b")
}

func TestTailVersionStops(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("a")+`{"v":2,"t":1,"type":"log"}`+"\n"+logLine("b"))
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "a")
	if _, ok := next(t, ch).(VersionMsg); !ok {
		t.Fatal("want VersionMsg")
	}
	expectNone(t, ch, 300*time.Millisecond)
}

func TestTailStopsOnCancel(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("a"))
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan any, 4)
	done := make(chan struct{})
	go func() { Tail(ctx, p, out); close(done) }()
	wantMsg(t, next(t, out), "a")
	cancel()
	select {
	case <-done:
	case <-time.After(deadline):
		t.Fatal("Tail did not return after cancel")
	}
}

func wantReset(t *testing.T, m any) {
	t.Helper()
	if _, ok := m.(ResetMsg); !ok {
		t.Fatalf("want ResetMsg, got %#v", m)
	}
}

func TestTailFollowsReplacedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("old1"))
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "old1")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, logLine("new1"))
	wantReset(t, next(t, ch))
	wantMsg(t, next(t, ch), "new1")
	appendFile(t, p, logLine("new2"))
	wantMsg(t, next(t, ch), "new2")
}

func TestTailHandlesTruncation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("aaaaaaaaaaaa")+logLine("bbbbbbbbbbbb"))
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "aaaaaaaaaaaa")
	wantMsg(t, next(t, ch), "bbbbbbbbbbbb")
	if err := os.WriteFile(p, []byte(logLine("c")), 0o644); err != nil {
		t.Fatal(err)
	}
	wantReset(t, next(t, ch))
	wantMsg(t, next(t, ch), "c")
}

func TestTailNeverReadsRotatedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("old1"))
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "old1")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	// Path is briefly missing: no error, no exit.
	expectNone(t, ch, 3*pollInterval)
	appendFile(t, p, logLine("new1"))
	wantReset(t, next(t, ch))
	for {
		m := next(t, ch)
		if got, ok := m.(Msg); ok {
			if got.Ev.Msg == "rotated-later" {
				t.Fatal("read rotated file")
			}
			if got.Ev.Msg == "new1" {
				break
			}
		}
	}
	appendFile(t, p+".1", logLine("rotated-later"))
	expectNone(t, ch, 3*pollInterval)
}

func TestTailResetDropsPartialLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("old1")+`{"v":1,"t":1,"type":"log","level":"info","msg":"par`)
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "old1")
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, logLine("new1"))
	wantReset(t, next(t, ch))
	wantMsg(t, next(t, ch), "new1") // not a malformed/joined line
}

func TestTailReplacementDoesNotLeakDescriptors(t *testing.T) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	appendFile(t, p, logLine("seed"))
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "seed")
	base := len(entries)
	for i := 0; i < 20; i++ {
		if err := os.Rename(p, p+".1"); err != nil {
			t.Fatal(err)
		}
		appendFile(t, p, logLine("x"))
		wantReset(t, next(t, ch))
		wantMsg(t, next(t, ch), "x")
	}
	entries, _ = os.ReadDir("/proc/self/fd")
	if len(entries) > base+2 {
		t.Fatalf("fd count grew from %d to %d", base, len(entries))
	}
}

func TestTailExitsOnCancelWhileMissing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	appendFile(t, p, logLine("a"))
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan any, 16)
	done := make(chan struct{})
	go func() { Tail(ctx, p, out); close(done) }()
	wantMsg(t, <-out, "a")
	os.Remove(p)
	cancel()
	select {
	case <-done:
	case <-time.After(deadline):
		t.Fatal("Tail did not exit on cancel")
	}
}

// An in-place rewrite that regrows past the old offset within one poll must
// still be detected (same inode, size >= old offset).
func TestTailDetectsInPlaceRewrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("old")+`{"v":1,"t":1,"type":"log","level":"info","msg":"par`)
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "old")
	expectNone(t, ch, 2*pollInterval) // partial line is held back
	var sb strings.Builder
	for i := 0; i < 6; i++ {
		sb.WriteString(logLine("new" + string(rune('0'+i))))
	}
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	wantReset(t, next(t, ch))
	for i := 0; i < 6; i++ {
		wantMsg(t, next(t, ch), "new"+string(rune('0'+i)))
	}
}

func startTailCap(t *testing.T, path string, maxLine int) <-chan any {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan any, 16)
	go tail(ctx, path, out, maxLine, false)
	return out
}

func TestTailOversizeLineWarnsOnceThenContinues(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	big := strings.Repeat("x", 200000) // spans many read chunks
	appendFile(t, p, logLine(big)+logLine("after"))
	ch := startTailCap(t, p, 1000)
	w, ok := next(t, ch).(WarnMsg)
	if !ok || !strings.Contains(w.Text, "too long") {
		t.Fatalf("want too-long WarnMsg, got %#v", w)
	}
	wantMsg(t, next(t, ch), "after")
	expectNone(t, ch, 2*pollInterval)
}

func TestTailOversizeUnterminatedLineThenNewline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, strings.Repeat("y", 5000)) // no newline yet
	ch := startTailCap(t, p, 1000)
	if _, ok := next(t, ch).(WarnMsg); !ok {
		t.Fatal("want WarnMsg")
	}
	appendFile(t, p, strings.Repeat("y", 5000)) // still the same line: no second warning
	expectNone(t, ch, 2*pollInterval)
	appendFile(t, p, "\n"+logLine("after"))
	wantMsg(t, next(t, ch), "after")
}

func TestTailLineJustUnderCapDecodes(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	const limit = 4096
	pad := limit - len(logLine("")) - 1 // line incl. newline is limit-1 bytes
	appendFile(t, p, logLine(strings.Repeat("z", pad)))
	ch := startTailCap(t, p, limit)
	m, ok := next(t, ch).(Msg)
	if !ok || len(m.Ev.Msg) != pad {
		t.Fatalf("got %#v", m)
	}
}

func TestTailWithEOFReportsConsumedOffset(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	first := logLine("a") + logLine("b")
	appendFile(t, p, first)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan any, 16)
	go TailWithEOF(ctx, p, ch)
	wantMsg(t, next(t, ch), "a")
	wantMsg(t, next(t, ch), "b")
	eof, ok := next(t, ch).(EOFMsg)
	if !ok || eof.Offset != int64(len(first)) {
		t.Fatalf("got %#v, want EOFMsg{Offset: %d}", eof, len(first))
	}
	// A partial trailing line counts as consumed: it is all there is to read.
	appendFile(t, p, `{"v":1,`)
	for {
		m := next(t, ch).(EOFMsg)
		if m.Offset == int64(len(first)+len(`{"v":1,`)) {
			break
		}
	}
}

func TestTailSendsNoEOFMsg(t *testing.T) {
	p := filepath.Join(t.TempDir(), "events.jsonl")
	appendFile(t, p, logLine("a"))
	ch := startTail(t, p)
	wantMsg(t, next(t, ch), "a")
	expectNone(t, ch, 300*time.Millisecond)
}

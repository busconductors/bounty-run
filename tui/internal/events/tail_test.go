package events

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
)

const deadline = 5 * time.Second

func startTail(t *testing.T, path string) <-chan tea.Msg {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	out := make(chan tea.Msg, 16)
	go Tail(ctx, path, out)
	return out
}

func next(t *testing.T, ch <-chan tea.Msg) tea.Msg {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(deadline):
		t.Fatal("timed out waiting for msg")
		return nil
	}
}

func expectNone(t *testing.T, ch <-chan tea.Msg, d time.Duration) {
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

func wantMsg(t *testing.T, m tea.Msg, text string) {
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
	out := make(chan tea.Msg, 4)
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

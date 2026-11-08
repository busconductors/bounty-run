package events

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	tea "charm.land/bubbletea/v2"
)

const pollInterval = 100 * time.Millisecond

func send(ctx context.Context, out chan<- tea.Msg, m tea.Msg) bool {
	select {
	case out <- m:
		return true
	case <-ctx.Done():
		return false
	}
}

// Tail replays path from offset 0 then follows appended lines, sending
// Msg/WarnMsg/VersionMsg on out until ctx is done. A partial trailing line is
// held back until its newline arrives.
func Tail(ctx context.Context, path string, out chan<- tea.Msg) {
	runDir := filepath.Dir(path)
	var f *os.File
	for f == nil {
		var err error
		if f, err = os.Open(path); err != nil {
			f = nil
			if !wait(ctx) {
				return
			}
		}
	}
	defer f.Close()

	r := bufio.NewReader(f)
	var pending []byte
	for {
		chunk, err := r.ReadBytes('\n')
		pending = append(pending, chunk...)
		if err == nil {
			line := bytes.TrimRight(pending, "\r\n")
			pending = nil
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			ev, derr := Decode(line)
			switch {
			case errors.Is(derr, ErrVersion):
				send(ctx, out, VersionMsg{RunDir: runDir})
				return
			case derr != nil:
				if !send(ctx, out, WarnMsg{RunDir: runDir, Text: fmt.Sprintf("skipped malformed event line: %v", derr)}) {
					return
				}
			default:
				if !send(ctx, out, Msg{RunDir: runDir, Ev: ev}) {
					return
				}
			}
			continue
		}
		if !errors.Is(err, io.EOF) {
			send(ctx, out, WarnMsg{RunDir: runDir, Text: fmt.Sprintf("read error: %v", err)})
			return
		}
		// EOF: keep partial bytes in pending, poll for more.
		if !wait(ctx) {
			return
		}
	}
}

func wait(ctx context.Context) bool {
	t := time.NewTimer(pollInterval)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

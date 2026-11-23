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
)

const pollInterval = 100 * time.Millisecond

func send(ctx context.Context, out chan<- any, m any) bool {
	select {
	case out <- m:
		return true
	case <-ctx.Done():
		return false
	}
}

// Tail replays path from offset 0 then follows appended lines, sending
// Msg/WarnMsg/VersionMsg on out until ctx is done. A partial trailing line is
// held back until its newline arrives. If the file is replaced (rename and
// recreate) or truncated, Tail sends ResetMsg, drops any held-back partial
// line and decoder state, and restarts at offset 0 of the new file. A path
// that is briefly missing is polled until it reappears.
func Tail(ctx context.Context, path string, out chan<- any) {
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
	defer func() { f.Close() }()

	cur, err := f.Stat()
	if err != nil {
		send(ctx, out, WarnMsg{RunDir: runDir, Text: fmt.Sprintf("read error: %v", err)})
		return
	}
	r := bufio.NewReader(f)
	var pending []byte
	var offset int64 // bytes consumed from f
	for {
		chunk, err := r.ReadBytes('\n')
		pending = append(pending, chunk...)
		offset += int64(len(chunk))
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
		// EOF: drained the current file. Check for replacement/truncation.
		ni, serr := os.Stat(path)
		switch {
		case serr != nil:
			// Missing between rename and recreate: keep polling.
		case !os.SameFile(cur, ni):
			nf, oerr := os.Open(path)
			if oerr != nil {
				break // raced with another replacement; retry next poll
			}
			info, ierr := nf.Stat()
			if ierr != nil {
				nf.Close()
				break
			}
			f.Close()
			f, cur = nf, info
			r = bufio.NewReader(f)
			pending, offset = nil, 0
			if !send(ctx, out, ResetMsg{}) {
				return
			}
			continue
		case ni.Size() < offset:
			if _, serr := f.Seek(0, io.SeekStart); serr != nil {
				send(ctx, out, WarnMsg{RunDir: runDir, Text: fmt.Sprintf("read error: %v", serr)})
				return
			}
			cur = ni
			r = bufio.NewReader(f)
			pending, offset = nil, 0
			if !send(ctx, out, ResetMsg{}) {
				return
			}
			continue
		}
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

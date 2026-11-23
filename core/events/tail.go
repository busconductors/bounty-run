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

// maxEventLine is the longest event line (including its newline) Tail will
// buffer. The engine caps lines at 1 MiB chars and JSON escaping can reach 12
// bytes per char, so valid lines stay under 16 MiB.
const maxEventLine = 16 << 20

// fingerprintLen is how many of the most recently consumed bytes are re-read
// at each EOF to detect an in-place rewrite of the file.
const fingerprintLen = 64

// Tail replays path from offset 0 then follows appended lines, sending
// Msg/WarnMsg/VersionMsg on out until ctx is done. A partial trailing line is
// held back until its newline arrives. If the file is replaced (rename and
// recreate), truncated or rewritten in place, Tail sends ResetMsg, drops any
// held-back partial line and decoder state, and restarts at offset 0. A path
// that is briefly missing is polled until it reappears. Lines longer than
// maxEventLine are skipped with one WarnMsg.
func Tail(ctx context.Context, path string, out chan<- any) {
	tail(ctx, path, out, maxEventLine)
}

func tail(ctx context.Context, path string, out chan<- any, maxLine int) {
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
	var (
		pending []byte
		fp      []byte // last fingerprintLen consumed bytes
		offset  int64  // bytes consumed from f
		discard bool   // skipping the rest of an oversize line
	)
	restart := func() {
		r = bufio.NewReader(f)
		pending, fp, offset, discard = nil, nil, 0, false
	}
	for {
		// Before reading from the file (nothing buffered), check whether it
		// was replaced, truncated or rewritten since the last read.
		if r.Buffered() == 0 {
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
				restart()
				if !send(ctx, out, ResetMsg{}) {
					return
				}
				continue
			case ni.Size() < offset || rewritten(f, fp, offset):
				if _, serr := f.Seek(0, io.SeekStart); serr != nil {
					send(ctx, out, WarnMsg{RunDir: runDir, Text: fmt.Sprintf("read error: %v", serr)})
					return
				}
				cur = ni
				restart()
				if !send(ctx, out, ResetMsg{}) {
					return
				}
				continue
			}
		}
		chunk, err := r.ReadSlice('\n') // bounded by the reader's buffer size
		offset += int64(len(chunk))
		fp = append(fp, chunk...)
		if len(fp) > fingerprintLen {
			fp = append(fp[:0], fp[len(fp)-fingerprintLen:]...)
		}
		complete := err == nil // chunk ended with a newline
		switch {
		case discard:
			discard = !complete
			complete = false
		case len(pending)+len(chunk) > maxLine:
			pending, discard = nil, !complete
			complete = false
			if !send(ctx, out, WarnMsg{RunDir: runDir, Text: fmt.Sprintf("skipped event line: too long (over %d bytes)", maxLine)}) {
				return
			}
		default:
			pending = append(pending, chunk...)
		}
		if complete {
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
		if err == nil || errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if !errors.Is(err, io.EOF) {
			send(ctx, out, WarnMsg{RunDir: runDir, Text: fmt.Sprintf("read error: %v", err)})
			return
		}
		if !wait(ctx) {
			return
		}
	}
}

// rewritten reports whether the bytes just before offset no longer match fp.
// A read error other than a short file is not treated as a mismatch.
func rewritten(f *os.File, fp []byte, offset int64) bool {
	if len(fp) == 0 {
		return false
	}
	buf := make([]byte, len(fp))
	n, err := f.ReadAt(buf, offset-int64(len(fp)))
	if n < len(buf) {
		return errors.Is(err, io.EOF) // file is shorter than what we consumed
	}
	return !bytes.Equal(buf, fp)
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

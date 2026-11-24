package shell

import (
	"log/slog"
	"reflect"
	"testing"
	"testing/fstest"
)

type recordingSink struct {
	name string
	data []any
}

func (r *recordingSink) Emit(name string, data ...any) bool {
	r.name, r.data = name, data
	return false
}

func TestEmitterForwardsChannelAndSinglePayload(t *testing.T) {
	for _, payload := range []any{map[string]int{"n": 1}, nil} {
		sink := &recordingSink{}
		emitter{events: sink}.Emit("run:event", payload)
		if sink.name != "run:event" || !reflect.DeepEqual(sink.data, []any{payload}) {
			t.Fatalf("got %q %#v, want one payload %#v", sink.name, sink.data, payload)
		}
	}
}

// Binding-call arguments (proxy, headers) are logged by Wails at debug level.
func TestSystemLogNeverDebug(t *testing.T) {
	opts := appOptions(fstest.MapFS{"index.html": {Data: []byte("x")}}, t.TempDir())
	if opts.Logger != nil || opts.LogLevel < slog.LevelInfo {
		t.Fatalf("logger %v level %v: binding arguments could be logged", opts.Logger, opts.LogLevel)
	}
}

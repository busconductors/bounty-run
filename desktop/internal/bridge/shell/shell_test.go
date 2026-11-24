package shell

import (
	"reflect"
	"testing"
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

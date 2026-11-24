package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"testing"

	"bountyrun/core/engine"
	"bountyrun/desktop/internal/catalog"
	"bountyrun/desktop/internal/runs"
)

// TestFrontendCallsExist checks that every bound method the frontend calls by
// name exists, so a rename on either side fails here and not at run time.
func TestFrontendCallsExist(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "frontend", "src", "lib", "bridge", "api.js"))
	if err != nil {
		t.Fatal(err)
	}
	pkg := regexp.MustCompile(`const PKG = '([^']+)'`).FindSubmatch(src)
	if pkg == nil || string(pkg[1]) != reflect.TypeFor[Launch]().PkgPath() {
		t.Fatalf("api.js PKG = %q, want %q", pkg, reflect.TypeFor[Launch]().PkgPath())
	}
	types := map[string]reflect.Type{"Launch": reflect.TypeFor[*Launch](), "Runs": reflect.TypeFor[*Runs](), "Doctor": reflect.TypeFor[*Doctor]()}
	calls := regexp.MustCompile(`call\('(\w+)\.(\w+)'`).FindAllSubmatch(src, -1)
	if len(calls) < 10 {
		t.Fatalf("found only %d calls in api.js", len(calls))
	}
	for _, c := range calls {
		typ, ok := types[string(c[1])]
		if !ok {
			t.Errorf("api.js calls unknown service %s", c[1])
			continue
		}
		if _, ok := typ.MethodByName(string(c[2])); !ok {
			t.Errorf("api.js calls %s.%s, which is not bound", c[1], c[2])
		}
	}
}

// TestRunsBindsNoLifecycleMethods keeps Close and friends off the frontend.
func TestRunsBindsNoLifecycleMethods(t *testing.T) {
	var names []string
	typ := reflect.TypeFor[*Runs]()
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}
	want := []string{"Attach", "Cancel", "Detach", "EngineLogTail", "HardKill", "ListRuns", "RunID", "ServiceShutdown", "Skip"}
	if !slices.Equal(names, want) {
		t.Fatalf("Runs methods = %v, want %v", names, want)
	}
}

// TestRunIDNamesTheBatchChannel: the frontend subscribes to run:<id>:batch
// before it attaches, so it needs the id Attach will emit on.
func TestRunIDNamesTheBatchChannel(t *testing.T) {
	r := &Runs{}
	for _, dir := range []string{"/o/a.com/20250101-000000", "/o/a.com/20250101-000000/", "/o/./a.com/x"} {
		if got, want := r.RunID(dir), runs.RunID(dir); got != want {
			t.Errorf("RunID(%q) = %q, want %q", dir, got, want)
		}
	}
}

func TestMarshalErrorKinds(t *testing.T) {
	cases := []struct {
		err  error
		want ErrorInfo
	}{
		{&runs.LaunchError{Dir: "/o/a.com/1", Tail: "usage: bad flag", Err: engine.ErrExited},
			ErrorInfo{Kind: "launch", Message: "engine exited before starting", Tail: "usage: bad flag", Dir: "/o/a.com/1"}},
		{fmt.Errorf("start: %w", &runs.LaunchError{Tail: "t", Outcome: "stopped", Err: engine.ErrNoStart}),
			ErrorInfo{Kind: "launch", Message: "engine did not start in time — stopped", Tail: "t"}},
		{runs.ErrCapReached, ErrorInfo{Kind: "cap", Message: runs.ErrCapReached.Error()}},
		{errors.New("invalid target"), ErrorInfo{Kind: "error", Message: "invalid target"}},
	}
	for _, c := range cases {
		var got ErrorInfo
		if err := json.Unmarshal(marshalError(c.err), &got); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("marshalError(%v) = %+v, want %+v", c.err, got, c.want)
		}
	}
}

func TestStartRejectsWhatPreviewRejects(t *testing.T) {
	root := t.TempDir()
	svc, err := runs.New(runs.Config{Root: root, EngineBin: "/nonexistent", Emitter: nop{}})
	if err != nil {
		t.Fatal(err)
	}
	stages := `{"schema":1,"stages":[{"id":"subs","num":1,"title":"S","tier":"passive"}]}`
	cat := catalog.New(catalog.Config{Root: root, EngineBin: "/nonexistent", Exec: func(string, ...string) ([]byte, error) {
		return []byte(stages), nil
	}})
	l := &Launch{cat: cat, runs: svc}
	r := catalog.Request{Options: engine.Options{Target: "example.com"}, Stages: []string{"warp"}}
	if _, err := l.Start(r); err == nil {
		t.Fatal("Start accepted an unknown stage")
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("rejected start left %d entries", len(entries))
	}
}

type nop struct{}

func (nop) Emit(string, any) {}

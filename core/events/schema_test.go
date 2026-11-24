package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// contractDir locates contract/ relative to this file, not the cwd.
func contractDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "contract")
}

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(contractDir(t), "events.v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// schemaErrors is a minimal validator covering only the keywords the schema
// uses: $ref, oneOf, const, enum, type, minimum, required, properties,
// additionalProperties, items.
func schemaErrors(root map[string]any, v any, s map[string]any, path string) []string {
	if ref, ok := s["$ref"].(string); ok {
		n := any(root)
		for _, p := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			n = n.(map[string]any)[p]
		}
		return schemaErrors(root, v, n.(map[string]any), path)
	}
	if one, ok := s["oneOf"].([]any); ok {
		matches := 0
		for _, o := range one {
			if len(schemaErrors(root, v, o.(map[string]any), path)) == 0 {
				matches++
			}
		}
		if matches != 1 {
			return []string{fmt.Sprintf("%s: matches %d of oneOf", path, matches)}
		}
		return nil
	}
	var out []string
	if c, ok := s["const"]; ok && !reflect.DeepEqual(v, c) {
		out = append(out, fmt.Sprintf("%s: want const %v", path, c))
	}
	if en, ok := s["enum"].([]any); ok {
		found := false
		for _, e := range en {
			found = found || reflect.DeepEqual(e, v)
		}
		if !found {
			out = append(out, fmt.Sprintf("%s: %v not in enum", path, v))
		}
	}
	if ty, ok := s["type"].(string); ok {
		good := false
		switch ty {
		case "object":
			_, good = v.(map[string]any)
		case "array":
			_, good = v.([]any)
		case "string":
			_, good = v.(string)
		case "integer":
			f, isNum := v.(float64)
			good = isNum && f == float64(int64(f))
		}
		if !good {
			return append(out, fmt.Sprintf("%s: not %s", path, ty))
		}
	}
	if min, ok := s["minimum"].(float64); ok {
		if f, isNum := v.(float64); isNum && f < min {
			out = append(out, path+": below minimum")
		}
	}
	if obj, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, has := obj[r.(string)]; !has {
					out = append(out, fmt.Sprintf("%s: missing %v", path, r))
				}
			}
		}
		for k, val := range obj {
			if ps, ok := props[k].(map[string]any); ok {
				out = append(out, schemaErrors(root, val, ps, path+"."+k)...)
				continue
			}
			switch ap := s["additionalProperties"].(type) {
			case bool:
				if !ap {
					out = append(out, fmt.Sprintf("%s: unexpected %s", path, k))
				}
			case map[string]any:
				out = append(out, schemaErrors(root, val, ap, path+"."+k)...)
			}
		}
	}
	if arr, ok := v.([]any); ok {
		if items, ok := s["items"].(map[string]any); ok {
			for i, e := range arr {
				out = append(out, schemaErrors(root, e, items, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	}
	return out
}

func validateLine(t *testing.T, root map[string]any, line []byte) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal(line, &v); err != nil {
		t.Fatalf("not JSON: %.80q: %v", line, err)
	}
	return schemaErrors(root, v, root, "$")
}

var wantTypes = []string{"run_start", "stage_start", "stage_end", "progress", "log", "output", "finding", "run_end"}

// Required fields per type, pinned so that loosening the schema fails.
var wantRequired = map[string][]string{
	"run_start":   {"target", "flags", "stages"},
	"stage_start": {"stage"},
	"stage_end":   {"stage", "status", "duration_ms", "counts"},
	"progress":    {"stage", "done", "total"},
	"log":         {"level", "msg"},
	"output":      {"stage", "tool", "stream", "line"},
	"finding":     {"severity", "template", "host", "url", "summary"},
	"run_end":     {"status", "totals", "report", "summary"},
}

// TestSchemaTypesMatchDecoder checks the schema's types, required fields and
// property names against what the Go decoder understands.
func TestSchemaTypesMatchDecoder(t *testing.T) {
	root := loadSchema(t)
	defs := root["$defs"].(map[string]any)
	var got []string
	for k := range defs {
		got = append(got, k)
	}
	sort.Strings(got)
	want := append([]string(nil), wantTypes...)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema types = %v, want %v", got, want)
	}
	if n := len(root["oneOf"].([]any)); n != 8 {
		t.Errorf("oneOf has %d entries, want 8", n)
	}

	tags := map[string]bool{}
	wt := reflect.TypeOf(wire{})
	for i := 0; i < wt.NumField(); i++ {
		tags[strings.Split(wt.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	for name, d := range defs {
		def := d.(map[string]any)
		var req []string
		for _, r := range def["required"].([]any) {
			req = append(req, r.(string))
		}
		if exp := append([]string{"v", "t", "type"}, wantRequired[name]...); !reflect.DeepEqual(req, exp) {
			t.Errorf("%s required = %v, want %v", name, req, exp)
		}
		for prop := range def["properties"].(map[string]any) {
			if !tags[prop] {
				t.Errorf("%s.%s is in the schema but the decoder has no field for it", name, prop)
			}
		}
		// The decoder accepts a minimal valid event of this type.
		ev := map[string]any{"v": 1, "t": 1, "type": name}
		for _, r := range wantRequired[name] {
			ev[r] = sampleValue(def["properties"].(map[string]any)[r].(map[string]any))
		}
		line, _ := json.Marshal(ev)
		if errs := validateLine(t, root, line); len(errs) != 0 {
			t.Errorf("%s sample invalid: %v", name, errs)
		}
		e, err := Decode(line)
		if err != nil || e.Type != name {
			t.Errorf("%s: decode = %+v, %v", name, e, err)
		}
	}
}

func sampleValue(p map[string]any) any {
	if en, ok := p["enum"].([]any); ok {
		return en[0]
	}
	switch p["type"] {
	case "integer":
		return 1
	case "array":
		return []any{}
	case "object":
		return map[string]any{}
	}
	return "x"
}

func readFixture(t *testing.T, path string) (complete [][]byte, tail []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.Split(b, []byte("\n"))
	return parts[:len(parts)-1], parts[len(parts)-1]
}

// TestGoldenFixturesDecode validates every golden fixture against the schema
// and decodes it with the client decoder.
func TestGoldenFixturesDecode(t *testing.T) {
	root := loadSchema(t)
	cdir := contractDir(t)
	tui := filepath.Join(cdir, "..", "tui", "internal", "ui", "testdata", "full_run.jsonl")
	files, err := filepath.Glob(filepath.Join(cdir, "testdata", "*.jsonl"))
	if err != nil || len(files) != 3 {
		t.Fatalf("contract fixtures = %v, %v", files, err)
	}
	files = append(files, tui)
	for _, f := range files {
		complete, tail := readFixture(t, f)
		if len(complete) == 0 {
			t.Errorf("%s: no complete lines", f)
		}
		for _, ln := range complete {
			if errs := validateLine(t, root, ln); len(errs) != 0 {
				t.Errorf("%s: %.80q: %v", filepath.Base(f), ln, errs)
			}
			if _, err := Decode(ln); err != nil {
				t.Errorf("%s: decode: %v", filepath.Base(f), err)
			}
		}
		if filepath.Base(f) == "partial_line.jsonl" {
			if len(tail) == 0 || json.Valid(tail) {
				t.Errorf("partial_line.jsonl must end in an unterminated, incomplete line")
			}
		} else if len(tail) != 0 {
			t.Errorf("%s: unexpected unterminated tail", filepath.Base(f))
		}
	}

	// Long line round-trips whole.
	complete, _ := readFixture(t, filepath.Join(cdir, "testdata", "long_line.jsonl"))
	if e, _ := Decode(complete[0]); len(e.Line) != 100*1024 {
		t.Errorf("long line = %d bytes, want %d", len(e.Line), 100*1024)
	}

	// Capped output: the warning decodes as a log event, not an output event.
	complete, _ = readFixture(t, filepath.Join(cdir, "testdata", "capped_output.jsonl"))
	var warns int
	for _, ln := range complete {
		e, _ := Decode(ln)
		if e.Type == "log" && e.Level == "warn" && strings.Contains(e.Msg, "capped") {
			warns++
		}
	}
	if warns != 1 {
		t.Errorf("capped warnings = %d, want 1", warns)
	}

	// An incompatible version is still rejected (existing TUI fixture).
	complete, _ = readFixture(t, filepath.Join(cdir, "..", "tui", "internal", "ui", "testdata", "incompatible.jsonl"))
	if _, err := Decode(complete[0]); !errors.Is(err, ErrVersion) {
		t.Errorf("incompatible fixture err = %v, want ErrVersion", err)
	}
}

// TestFakeRunValidatesAgainstSchema validates real engine output.
func TestFakeRunValidatesAgainstSchema(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	root := loadSchema(t)
	repo := filepath.Join(contractDir(t), "..")
	out := filepath.Join(t.TempDir(), "events.jsonl")
	cmd := exec.Command(py, filepath.Join(repo, "tests", "fixtures", "fake_run.py"), out)
	cmd.Dir = repo
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fake_run.py: %v\n%s", err, b)
	}
	complete, _ := readFixture(t, out)
	seen := map[string]bool{}
	for _, ln := range complete {
		if errs := validateLine(t, root, ln); len(errs) != 0 {
			t.Errorf("%.80q: %v", ln, errs)
		}
		e, err := Decode(ln)
		if err != nil {
			t.Fatal(err)
		}
		seen[e.Type] = true
	}
	if len(seen) != 8 {
		t.Errorf("fake run covered %v, want all 8 types", seen)
	}
}

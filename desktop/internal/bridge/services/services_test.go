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
	types := map[string]reflect.Type{"Launch": reflect.TypeFor[*Launch](), "Runs": reflect.TypeFor[*Runs](), "Doctor": reflect.TypeFor[*Doctor](), "Findings": reflect.TypeFor[*Findings](), "Reports": reflect.TypeFor[*Reports]()}
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

func TestReportsOpenExternalValidates(t *testing.T) {
	root := t.TempDir()
	run := filepath.Join(root, "ex.com", "20250101-000000")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"FINDINGS.md", "findings.json", "summary.html"} {
		if err := os.WriteFile(filepath.Join(run, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var opened []string
	r := &Reports{root: root, open: func(p string) error { opened = append(opened, p); return nil },
		runDir: func(d string) (string, error) {
			if filepath.Dir(filepath.Dir(d)) != root {
				return "", errors.New("not a run dir")
			}
			return d, nil
		}}
	if err := r.OpenExternal(run, "FINDINGS.md"); err != nil || len(opened) != 1 {
		t.Fatalf("err %v opened %v", err, opened)
	}
	for _, name := range []string{"findings.json", "summary.html", "../FINDINGS.md", "/etc/passwd"} {
		if err := r.OpenExternal(run, name); err == nil {
			t.Errorf("%s opened", name)
		}
	}
	// SUMMARY.md is allowlisted: refused only while the file is missing.
	if err := r.OpenExternal(run, "SUMMARY.md"); err == nil {
		t.Error("missing SUMMARY.md opened")
	}
	if err := os.WriteFile(filepath.Join(run, "SUMMARY.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.OpenExternal(run, "SUMMARY.md"); err != nil {
		t.Errorf("present SUMMARY.md: %v", err)
	}
	opened = opened[:1]
	if err := r.OpenExternal(t.TempDir(), "FINDINGS.md"); err == nil {
		t.Error("foreign dir opened")
	}
	if len(opened) != 1 {
		t.Errorf("opened %v", opened)
	}
	info, err := r.Available(run)
	if err != nil || !info.HTML || !slices.Equal(info.Markdown, []string{"FINDINGS.md", "SUMMARY.md"}) {
		t.Errorf("available %+v %v", info, err)
	}
}

func pdfReports(t *testing.T) (*Reports, string, *[]string) {
	t.Helper()
	root := t.TempDir()
	run := filepath.Join(root, "ex.com", "20250101-000000")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	opened := &[]string{}
	r := &Reports{root: root, open: func(p string) error { *opened = append(*opened, p); return nil },
		runDir: func(d string) (string, error) { return d, nil }}
	return r, run, opened
}

func TestAvailableReportsPDF(t *testing.T) {
	r, run, _ := pdfReports(t)
	info, err := r.Available(run)
	if err != nil || info.PDF {
		t.Fatalf("absent: %+v %v", info, err)
	}
	if err := os.WriteFile(filepath.Join(run, "report.pdf"), []byte("%PDF"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err = r.Available(run)
	if err != nil || !info.PDF {
		t.Fatalf("present: %+v %v", info, err)
	}
}

func TestExportPDFValidatesRunDirAndTarget(t *testing.T) {
	r, run, _ := pdfReports(t)
	var calls []string
	orig := renderReportPDF
	t.Cleanup(func() { renderReportPDF = orig })
	renderReportPDF = func(htmlPath, pdfPath, theme string) error {
		calls = append(calls, pdfPath)
		return os.WriteFile(pdfPath, []byte("%PDF-stub"), 0o600)
	}

	// (a) no summary.html: an error, the renderer is never called, no report.pdf.
	if _, err := r.ExportPDF(run, "light"); err == nil {
		t.Error("export without summary.html succeeded")
	}
	if len(calls) != 0 {
		t.Errorf("renderer ran without summary.html: %v", calls)
	}
	if _, err := os.Stat(filepath.Join(run, "report.pdf")); err == nil {
		t.Error("report.pdf written without summary.html")
	}

	// (b) with summary.html: returns <runDir>/report.pdf and the stub produced it.
	if err := os.WriteFile(filepath.Join(run, "summary.html"), []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := r.ExportPDF(run, "dark")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	want := filepath.Join(run, "report.pdf")
	if got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if len(calls) != 1 || calls[0] != want {
		t.Errorf("renderer calls = %v, want [%q]", calls, want)
	}
	if b, err := os.ReadFile(want); err != nil || string(b) != "%PDF-stub" {
		t.Errorf("report.pdf = %q (%v), want stub output", b, err)
	}
}

func TestOpenExternalAllowsPDFRejectsOther(t *testing.T) {
	r, run, opened := pdfReports(t)
	for _, n := range []string{"report.pdf", "findings.json"} {
		if err := os.WriteFile(filepath.Join(run, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.OpenExternal(run, "report.pdf"); err != nil || len(*opened) != 1 {
		t.Fatalf("err %v opened %v", err, *opened)
	}
	if err := r.OpenExternal(run, "findings.json"); err == nil {
		t.Error("findings.json opened")
	}
}

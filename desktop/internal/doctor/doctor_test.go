package doctor

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"bountyrun/desktop/internal/catalog"
)

const stagesJSON = `{"schema":1,"stages":[
 {"id":"subs","num":1,"title":"SUBS","tier":"passive","caps":[],"opt_in":false,"parent":null},
 {"id":"nmap","num":6,"title":"NMAP","tier":"intrusive","caps":[],"opt_in":true,"parent":null},
 {"id":"tech","num":19,"title":"TECH","tier":"active","caps":[],"opt_in":false,"parent":null}]}`

const doctorJSON = `{"schema":1,"tools":[
 {"name":"subfinder","path":"/usr/bin/subfinder","version":"2.6.0","required_by":["subs"],"optional":false,"install_hint":"go install","status":"ok"},
 {"name":"amass","path":null,"version":null,"required_by":["subs"],"optional":true,"install_hint":"","status":"missing"},
 {"name":"whatweb","path":null,"version":null,"required_by":["tech"],"optional":false,"install_hint":"sudo apt install whatweb","status":"missing"},
 {"name":"shcheck","path":"/opt/shcheck.py","version":null,"required_by":["tech"],"optional":false,"install_hint":"vendored","status":"unknown_version"},
 {"name":"weird","path":null,"version":null,"required_by":[],"optional":false,"install_hint":"","status":"exploded"}]}`

func service(doctorOut []byte, doctorErr error) *Service {
	cat := catalog.New(catalog.Config{Root: os.TempDir(), EngineBin: "/fake/bounty-run", Exec: func(_ string, args ...string) ([]byte, error) {
		if args[1] == "stages" {
			return []byte(stagesJSON), nil
		}
		return doctorOut, doctorErr
	}})
	return New(cat)
}

func TestDoctorParsesIntrospect(t *testing.T) {
	rep, err := service([]byte(doctorJSON), nil).Report()
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]Row{}
	for _, r := range rep.Rows {
		rows[r.Name] = r
	}
	if len(rep.Rows) != 5 {
		t.Fatalf("rows = %d, want 5", len(rep.Rows))
	}
	if r := rows["subfinder"]; r.Status != StatusOK || r.Version != "2.6.0" || r.Path != "/usr/bin/subfinder" {
		t.Fatalf("subfinder row = %+v", r)
	}
	if r := rows["shcheck"]; r.Status != StatusOK {
		t.Fatalf("a tool with no version string is present, got %+v", r)
	}
	w := rows["whatweb"]
	if w.Status != StatusMissing || w.Guidance != "sudo apt install whatweb" || !slices.Equal(w.Affects, []string{"tech"}) {
		t.Fatalf("whatweb row = %+v", w)
	}
	// An optional tool is also the modifier of its own name; no hint gets generic guidance.
	a := rows["amass"]
	if a.Status != StatusMissing || !a.Optional || !strings.Contains(a.Guidance, "amass") || !strings.Contains(a.Guidance, "PATH") {
		t.Fatalf("amass row = %+v", a)
	}
	if !slices.Equal(a.Affects, []string{"subs", "amass"}) {
		t.Fatalf("amass affects = %v", a.Affects)
	}
	if rows["weird"].Status != StatusError {
		t.Fatalf("unknown status must be error, got %+v", rows["weird"])
	}
	if rep.Missing != 2 {
		t.Fatalf("missing = %d, want 2", rep.Missing)
	}
}

func TestDoctorEngineMissing(t *testing.T) {
	_, err := service(nil, os.ErrNotExist).Report()
	if err == nil || !strings.Contains(err.Error(), "introspect doctor") {
		t.Fatalf("err = %v, want an engine failure", err)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err %v does not wrap the cause", err)
	}
}

func TestDoctorMalformedJSON(t *testing.T) {
	_, err := service([]byte(`{"schema":1,"tools":[`), nil).Report()
	if err == nil || !strings.Contains(err.Error(), "bad JSON") {
		t.Fatalf("err = %v, want bad JSON", err)
	}
}

func TestRecheckRunsAgain(t *testing.T) {
	n := 0
	cat := catalog.New(catalog.Config{Root: os.TempDir(), EngineBin: "/fake", Exec: func(_ string, args ...string) ([]byte, error) {
		if args[1] == "stages" {
			return []byte(stagesJSON), nil
		}
		n++
		return []byte(doctorJSON), nil
	}})
	s := New(cat)
	s.Report()
	s.Report()
	if n != 1 {
		t.Fatalf("Report ran the check %d times, want cached", n)
	}
	if _, err := s.Recheck(); err != nil || n != 2 {
		t.Fatalf("Recheck err=%v runs=%d", err, n)
	}
}

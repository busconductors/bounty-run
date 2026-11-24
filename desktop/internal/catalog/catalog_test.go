package catalog

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"bountyrun/core/engine"
	"bountyrun/desktop/internal/runs"
)

// stagesJSON mirrors the shape of `bounty-run introspect stages`.
const stagesJSON = `{"schema":1,"stages":[
 {"id":"subs","num":1,"title":"SUBDOMAIN ENUMERATION","tier":"passive","caps":[],"opt_in":false,"parent":null},
 {"id":"origin","num":5,"title":"ORIGIN HUNTING","tier":"active","caps":[],"opt_in":false,"parent":null},
 {"id":"origin_deep","num":5,"title":"ORIGIN HUNTING","tier":"active","caps":[],"opt_in":false,"parent":"origin"},
 {"id":"nmap","num":6,"title":"PORT SCAN (NMAP)","tier":"intrusive","caps":[],"opt_in":true,"parent":null},
 {"id":"tls","num":9,"title":"TLS/SSL ANALYSIS (SSLYZE)","tier":"active","caps":[],"opt_in":true,"parent":null},
 {"id":"vuln","num":11,"title":"VULNERABILITY SCAN (NUCLEI)","tier":"active","caps":["oast"],"opt_in":false,"parent":null},
 {"id":"param","num":14,"title":"PARAMETER / SQLi SCAN","tier":"intrusive","caps":[],"opt_in":false,"parent":null},
 {"id":"tech","num":19,"title":"TECH DETECTION","tier":"active","caps":[],"opt_in":false,"parent":null}]}`

// doctorJSON mirrors `bounty-run introspect doctor`: whatweb (required by
// tech) and nmap, amass, dnsx (optional) are missing; shcheck carries no
// version string and must not count as missing.
const doctorJSON = `{"schema":1,"tools":[
 {"name":"subfinder","path":"/usr/bin/subfinder","version":"2.6.0","required_by":["subs"],"optional":false,"install_hint":"go install","status":"ok"},
 {"name":"amass","path":null,"version":null,"required_by":["subs"],"optional":true,"install_hint":"see amass","status":"missing"},
 {"name":"dnsx","path":null,"version":null,"required_by":["subs"],"optional":true,"install_hint":"go install","status":"missing"},
 {"name":"nmap","path":null,"version":null,"required_by":["nmap"],"optional":true,"install_hint":"sudo apt install nmap","status":"missing"},
 {"name":"whatweb","path":null,"version":null,"required_by":["tech"],"optional":false,"install_hint":"sudo apt install whatweb","status":"missing"},
 {"name":"shcheck","path":"/opt/shcheck.py","version":null,"required_by":["headers","tech"],"optional":false,"install_hint":"vendored","status":"unknown_version"}]}`

const versionJSON = `{"schema":1,"engine_version":"1.2.0","events_schema":1}`

// fakeEngine writes a Python bounty-run that answers introspect from the
// constants above and, for a scan, records its argv and environment in the run
// dir and emits run_start like runner/events.py. It never touches a network.
func fakeEngine(t *testing.T, stages string) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available for the fake engine")
	}
	src := `#!` + py + ` -I
import json, os, sys, time
REPORTS = {"stages": ` + "r'''" + stages + "'''" + `, "doctor": ` + "r'''" + doctorJSON + "'''" + `,
           "version": ` + "r'''" + versionJSON + "'''" + `}
argv = sys.argv[1:]
if argv[:1] == ["introspect"]:
    sys.stdout.write(json.dumps(json.loads(REPORTS[argv[1]])) + "\n")
    sys.exit(0)
run_dir = argv[argv.index("-o") + 1]
ev_path = argv[argv.index("--events") + 1]
open(os.path.join(run_dir, "spawn.json"), "w").write(json.dumps({
    "argv": sys.argv,
    "env": sorted(k for k in os.environ if k.startswith("BOUNTY_RUN_"))}))
s = open("/proc/self/stat").read()
open(os.path.join(run_dir, "run.json"), "w").write(json.dumps({
    "pid": os.getpid(), "pgid": os.getpgrp(),
    "pid_start": int(s.rsplit(")", 1)[1].split()[19]),
    "target": argv[0], "flags": {}, "started": int(time.time() * 1000)}))
with open(ev_path, "a") as ev:
    for typ, kw in (("run_start", {"target": argv[0], "flags": {}, "stages": []}),
                    ("run_end", {"status": "ok", "totals": {}, "report": "", "summary": ""})):
        kw.update(v=1, t=int(time.time() * 1000), type=typ)
        ev.write(json.dumps(kw) + "\n")
`
	path := filepath.Join(t.TempDir(), "bounty-run")
	if err := os.WriteFile(path, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestCatalog(t *testing.T) (*Catalog, string) {
	t.Helper()
	bin := fakeEngine(t, stagesJSON)
	root := filepath.Join(t.TempDir(), "outputs")
	return New(Config{Root: root, EngineBin: bin}), bin
}

// req enables stages at the intrusive ceiling unless the test overrides it.
func req(target string, stages ...string) Request {
	return Request{Options: engine.Options{Target: target, Intensity: "intrusive"}, Stages: stages}
}

const (
	proxyWarning  = "Proxy set: nmap and DNS stay direct, tools that cannot use the proxy are skipped, no origin IP is scanned, and child tools can expose proxy credentials in the local process list."
	scopeWarning  = "--scope-allow set: it replaces the default target-plus-subdomains scope."
	unredactedMsg = "--evidence-unredacted set: stored evidence may contain secrets."
	missingPrefix = "Selected stage has a missing tool"
)

func TestStagesFromEngine(t *testing.T) {
	c, _ := newTestCatalog(t)
	stages, err := c.Stages()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range stages {
		ids = append(ids, s.ID)
	}
	want := []string{"subs", "origin", "origin_deep", "nmap", "tls", "vuln", "param", "tech"}
	if !slices.Equal(ids, want) {
		t.Fatalf("stage ids = %v, want %v", ids, want)
	}
	nmap := stages[3]
	if !nmap.OptIn || nmap.Tier != "intrusive" || nmap.Num != 6 || nmap.Title != "PORT SCAN (NMAP)" {
		t.Fatalf("nmap = %+v", nmap)
	}
	if stages[2].Parent != "origin" || stages[5].Caps[0] != "oast" {
		t.Fatalf("parent/caps not carried: %+v %+v", stages[2], stages[5])
	}
}

func TestStagesRejectMalformedReports(t *testing.T) {
	for name, report := range map[string]string{
		"schema":    `{"schema":2,"stages":[]}`,
		"empty":     `{"schema":1,"stages":[]}`,
		"bad id":    `{"schema":1,"stages":[{"id":"a b","num":1,"title":"X","tier":"active"}]}`,
		"bad tier":  `{"schema":1,"stages":[{"id":"a","num":1,"title":"X","tier":"loud"}]}`,
		"duplicate": `{"schema":1,"stages":[{"id":"a","num":1,"title":"X","tier":"active"},{"id":"a","num":2,"title":"Y","tier":"active"}]}`,
		"orphan":    `{"schema":1,"stages":[{"id":"a","num":1,"title":"X","tier":"active","parent":"zz"}]}`,
	} {
		c := New(Config{Root: t.TempDir(), EngineBin: fakeEngine(t, report)})
		if _, err := c.Stages(); err == nil {
			t.Errorf("%s: malformed stage report accepted", name)
		}
	}
}

func TestStagesUseInjectedCommand(t *testing.T) {
	var calls [][]string
	c := New(Config{Root: t.TempDir(), EngineBin: "/fake/bounty-run", Exec: func(bin string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{bin}, args...))
		return []byte(stagesJSON), nil
	}})
	if _, err := c.Stages(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stages(); err != nil { // cached
		t.Fatal(err)
	}
	if len(calls) != 1 || !slices.Equal(calls[0], []string{"/fake/bounty-run", "introspect", "stages"}) {
		t.Fatalf("engine calls = %v", calls)
	}
}

func TestDoctorUnknownVersionIsNotMissing(t *testing.T) {
	c, _ := newTestCatalog(t)
	d, err := c.Doctor()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Tools) != 6 {
		t.Fatalf("got %d tools", len(d.Tools))
	}
	if got := d.MissingByStage["tech"]; !slices.Equal(got, []string{"whatweb"}) {
		t.Fatalf("tech missing = %v, want [whatweb] (shcheck unknown_version is present)", got)
	}
	if _, ok := d.MissingByStage["headers"]; ok {
		t.Fatal("unknown_version shcheck reported as missing")
	}
	// An optional helper of a default stage (dnsx for subs) degrades
	// gracefully; an optional tool that is the opt-in stage's own tool does not.
	if got := d.MissingByStage["subs"]; len(got) != 0 {
		t.Fatalf("subs missing = %v, want none", got)
	}
	if got := d.MissingByStage["nmap"]; !slices.Equal(got, []string{"nmap"}) {
		t.Fatalf("nmap missing = %v", got)
	}
	if got := d.MissingByStage["amass"]; !slices.Equal(got, []string{"amass"}) {
		t.Fatalf("amass modifier missing = %v", got)
	}
}

func TestResolveStageSelection(t *testing.T) {
	c, _ := newTestCatalog(t)
	o, err := c.Resolve(req("Example.COM", "subs", "origin", "nmap", "nmap-full", "vuln"))
	if err != nil {
		t.Fatal(err)
	}
	if o.Target != "example.com" || !o.Nmap || !o.NmapFull || o.TLS || o.Amass {
		t.Fatalf("flags wrong: %+v", o)
	}
	if want := []string{"origin_deep", "param", "tech"}; !slices.Equal(o.Skip, want) {
		t.Fatalf("skip = %v, want %v", o.Skip, want)
	}

	// Stages above the ceiling are gated by the engine: neither flagged nor skipped.
	r := req("example.com", "subs", "nmap", "nmap-full", "tech")
	r.Options.Intensity = "active"
	o, err = c.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	if o.Nmap || o.NmapFull || slices.Contains(o.Skip, "param") || slices.Contains(o.Skip, "nmap") {
		t.Fatalf("above-ceiling stages leaked into flags: %+v", o)
	}

	// Stage fields the client sends are replaced by the selection.
	r = req("example.com", "subs")
	r.Options.Headi, r.Options.Skip = true, []string{"subs"}
	if o, err = c.Resolve(r); err != nil || o.Headi || slices.Contains(o.Skip, "subs") {
		t.Fatalf("client stage fields not overridden: %+v %v", o, err)
	}
}

func TestPreviewRejectsBadInput(t *testing.T) {
	c, _ := newTestCatalog(t)
	bad := map[string]func(*Request){
		"target":        func(r *Request) { r.Options.Target = "not a domain" },
		"intensity":     func(r *Request) { r.Options.Intensity = "loud" },
		"unknown stage": func(r *Request) { r.Stages = append(r.Stages, "warp") },
		"no stage":      func(r *Request) { r.Stages = nil },
		"rate +Inf":     func(r *Request) { r.Options.RateLimit = math.Inf(1) },
		"rate NaN":      func(r *Request) { r.Options.RateLimit = math.NaN() },
		"rate high":     func(r *Request) { r.Options.RateLimit = 5000 },
		"rate low":      func(r *Request) { r.Options.RateLimit = 0.01 },
		"proxy":         func(r *Request) { r.Options.Proxy = "ftp://x:1" },
		"header CRLF":   func(r *Request) { r.Options.Headers = []string{"X-A: 1\r\nX-B: 2"} },
		"header name":   func(r *Request) { r.Options.Headers = []string{"no colon"} },
		"scope newline": func(r *Request) { r.Options.ScopeAllow = []string{"a.com\nb.com"} },
	}
	for name, mutate := range bad {
		r := req("example.com", "subs")
		mutate(&r)
		if _, err := c.Preview(r); err == nil {
			t.Errorf("%s: bad input previewed", name)
		}
		if _, err := c.Resolve(r); err == nil {
			t.Errorf("%s: bad input resolved", name)
		}
	}
}

func TestPreviewNeverContainsSecrets(t *testing.T) {
	c, _ := newTestCatalog(t)
	r := req("example.com", "subs", "tech")
	r.Options.Proxy = "http://user:proxysecret@127.0.0.1:8080"
	r.Options.Headers = []string{"Authorization: Bearer headersecret", "Cookie: sid=cookiesecret"}
	p, err := c.Preview(r)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(p)
	for _, secret := range []string{"proxysecret", "headersecret", "cookiesecret", "Authorization", "Bearer", "127.0.0.1:8080"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("preview leaks %q: %s", secret, b)
		}
	}
	for _, name := range []string{engine.ProxyEnvVar, engine.HeadersEnvVar} {
		if !slices.Contains(p.EnvNames, name) {
			t.Fatalf("EnvNames %v lacks %s", p.EnvNames, name)
		}
	}
}

func TestPreviewWarningsForProxy(t *testing.T) {
	c, _ := newTestCatalog(t)
	p, err := c.Preview(req("example.com", "subs"))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.Warnings, proxyWarning) {
		t.Fatal("proxy warning without a proxy")
	}
	r := req("example.com", "subs")
	r.Options.Proxy = "socks5h://127.0.0.1:9050"
	if p, err = c.Preview(r); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Warnings, proxyWarning) {
		t.Fatalf("warnings = %q, want the proxy warning", p.Warnings)
	}
}

func TestPreviewWarnsScopeAllowReplaces(t *testing.T) {
	c, _ := newTestCatalog(t)
	p, err := c.Preview(req("Example.com", "subs"))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.Warnings, scopeWarning) {
		t.Fatal("scope warning without --scope-allow")
	}
	if !p.Scope.Default || !slices.Equal(p.Scope.Allow, []string{"example.com", "*.example.com"}) {
		t.Fatalf("default scope = %+v", p.Scope)
	}
	r := req("example.com", "subs")
	r.Options.ScopeAllow = []string{" api.example.com ", "", "10.0.0.0/8"}
	r.Options.ScopeDeny = []string{"admin.example.com"}
	if p, err = c.Preview(r); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Warnings, scopeWarning) {
		t.Fatalf("warnings = %q, want the scope-allow warning", p.Warnings)
	}
	if p.Scope.Default || !slices.Equal(p.Scope.Allow, []string{"api.example.com", "10.0.0.0/8"}) ||
		!slices.Equal(p.Scope.Deny, []string{"admin.example.com"}) {
		t.Fatalf("effective scope = %+v", p.Scope)
	}
	if !slices.Contains(p.Argv, "--scope-allow=api.example.com") {
		t.Fatalf("argv lacks the trimmed rule: %v", p.Argv)
	}
}

func TestPreviewWarnsEvidenceUnredacted(t *testing.T) {
	c, _ := newTestCatalog(t)
	r := req("example.com", "subs")
	r.Options.EvidenceUnredacted = true
	p, err := c.Preview(r)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Warnings, unredactedMsg) {
		t.Fatalf("warnings = %q", p.Warnings)
	}
}

func TestPreviewWarnsMissingTool(t *testing.T) {
	c, _ := newTestCatalog(t)
	count := func(r Request) []string {
		t.Helper()
		p, err := c.Preview(r)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, w := range p.Warnings {
			if strings.HasPrefix(w, missingPrefix) {
				out = append(out, w)
			}
		}
		return out
	}
	if w := count(req("example.com", "subs", "origin")); len(w) != 0 {
		t.Fatalf("unexpected missing-tool warnings: %q", w)
	}
	w := count(req("example.com", "subs", "tech", "nmap", "amass"))
	if len(w) != 3 || !strings.Contains(strings.Join(w, "|"), "whatweb") {
		t.Fatalf("missing-tool warnings = %q, want tech, nmap and amass", w)
	}
	// nmap above the ceiling will not run, so its missing tool is moot.
	r := req("example.com", "subs", "nmap")
	r.Options.Intensity = "active"
	if w := count(r); len(w) != 0 {
		t.Fatalf("warned about a gated stage: %q", w)
	}
}

// TestPreviewEqualsSpawnedArgv launches the request through runs.Service and
// compares the engine's real argv with the preview. The only difference
// allowed is the run directory: the preview shows RunDirPlaceholder where
// StartRun substitutes the freshly made dir.
func TestPreviewEqualsSpawnedArgv(t *testing.T) {
	c, bin := newTestCatalog(t)
	svc, err := runs.New(runs.Config{Root: c.root, EngineBin: bin, Emitter: nopEmitter{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Close)
	r := req("Example.com", "subs", "origin", "nmap", "nmap-full", "tech", "amass")
	r.Options.Proxy = "http://u:p@127.0.0.1:8080"
	r.Options.Headers = []string{"X-Test: 1"}
	r.Options.ScopeAllow = []string{"*.example.com"}
	r.Options.RateLimit = 2.5
	r.Options.EvidenceUnredacted = true
	r.Options.UserAgent = "-weird agent"

	p, err := c.Preview(r)
	if err != nil {
		t.Fatal(err)
	}
	o, err := c.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := svc.StartRun(o)
	if err != nil {
		t.Fatal(err)
	}
	var spawned struct {
		Argv []string
		Env  []string
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join(ref.Dir, "spawn.json"))
		if err == nil && json.Unmarshal(b, &spawned) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("engine never recorded its argv")
		}
		time.Sleep(20 * time.Millisecond)
	}
	want := make([]string, len(p.Argv))
	for i, a := range p.Argv {
		want[i] = strings.ReplaceAll(a, p.RunDir, ref.Dir)
	}
	if p.RunDir != filepath.Join(c.root, "example.com", RunDirPlaceholder) {
		t.Fatalf("RunDir = %q", p.RunDir)
	}
	if !slices.Equal(spawned.Argv, want) {
		t.Fatalf("spawned argv differs from preview\nspawned: %q\npreview: %q", spawned.Argv, want)
	}
	if got := slices.Sorted(slices.Values(p.EnvNames)); !slices.Equal(got, spawned.Env) {
		t.Fatalf("EnvNames %v, engine saw %v", got, spawned.Env)
	}
}

type nopEmitter struct{}

func (nopEmitter) Emit(string, any) {}

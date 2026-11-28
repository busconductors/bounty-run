package engine

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestArgvLegacyOptionsUnchanged(t *testing.T) {
	base := []string{"a.com", "-o", "/d", "--events", "/d/events.jsonl", "--no-banner"}
	with := func(extra ...string) []string { return append(slices.Clone(base), extra...) }
	cases := []struct {
		name string
		o    Options
		want []string
	}{
		{"bare", Options{Target: "a.com"}, base},
		{"skip", Options{Target: "a.com", TLS: true, Skip: []string{"dork", "param"}}, with("--tls", "--skip", "dork,param")},
		{"all", Options{Target: "a.com", Amass: true, TLS: true, Nikto: true, Nmap: true, Metis: true, Headi: true, Noauth: true, NmapFull: true,
			Skip: []string{"cf"}, Timeout: 30, MaxParamURLs: 5, Proxy: "http://u:p@h:1"},
			with("--amass", "--tls", "--nikto", "--nmap", "--metis", "--headi", "--noauth", "--nmap-full", "--skip", "cf", "--timeout", "30", "--max-param-urls", "5")},
		{"nmap-full without nmap", Options{Target: "a.com", NmapFull: true}, base},
	}
	for _, c := range cases {
		if got := Argv(c.o, "/d"); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestArgvEachNewFlag(t *testing.T) {
	three := 3
	zero := 0
	cases := []struct {
		name string
		o    Options
		want []string
	}{
		{"intensity", Options{Intensity: "passive"}, []string{"--intensity", "passive"}},
		{"findomain", Options{Findomain: true}, []string{"--findomain"}},
		{"resolvers", Options{Resolvers: "/r.txt"}, []string{"--resolvers=/r.txt"}},
		{"dns-rate", Options{DNSRate: 300}, []string{"--dns-rate", "300"}},
		{"no-subs-cache", Options{NoSubsCache: true}, []string{"--no-subs-cache"}},
		{"threads", Options{Threads: 10}, []string{"--threads", "10"}},
		{"no-oast", Options{NoOAST: true}, []string{"--no-oast"}},
		{"scope-allow", Options{ScopeAllow: []string{"*.a.com", "10.0.0.0/8"}}, []string{"--scope-allow=*.a.com", "--scope-allow=10.0.0.0/8"}},
		{"scope-deny", Options{ScopeDeny: []string{"x.a.com"}}, []string{"--scope-deny=x.a.com"}},
		{"scope-file", Options{ScopeFile: "/s.txt"}, []string{"--scope-file=/s.txt"}},
		{"user-agent", Options{UserAgent: "-weird agent"}, []string{"--user-agent=-weird agent"}},
		{"rate-limit", Options{RateLimit: 2.5}, []string{"--rate-limit", "2.5"}},
		{"retries", Options{Retries: &three}, []string{"--retries", "3"}},
		{"retries zero set", Options{Retries: &zero}, []string{"--retries", "0"}},
		{"verify-tls", Options{VerifyTLS: true}, []string{"--verify-tls"}},
		{"no-evidence", Options{NoEvidence: true}, []string{"--no-evidence"}},
		{"evidence-unredacted", Options{EvidenceUnredacted: true}, []string{"--evidence-unredacted"}},
		{"evidence-max-body", Options{EvidenceMaxBody: 1000}, []string{"--evidence-max-body", "1000"}},
		{"max-hosts", Options{MaxHosts: 50}, []string{"--max-hosts", "50"}},
		{"wordlist", Options{Wordlist: "/w.txt"}, []string{"--wordlist=/w.txt"}},
		{"nuclei-severity", Options{NucleiSeverity: "high,critical"}, []string{"--nuclei-severity=high,critical"}},
		{"nuclei-c", Options{NucleiC: 5}, []string{"--nuclei-c", "5"}},
		{"nuclei-timeout", Options{NucleiTimeout: 600}, []string{"--nuclei-timeout", "600"}},
		{"refresh-ipintel", Options{RefreshIPIntel: true}, []string{"--refresh-ipintel"}},
		{"ipintel-offline", Options{IPIntelOffline: true}, []string{"--ipintel-offline"}},
		{"no-track", Options{NoTrack: true}, []string{"--no-track"}},
		{"headers never in argv", Options{Headers: []string{"X-A: b"}}, nil},
		{"zero values", Options{}, nil},
	}
	legacy := Argv(Options{Target: "a.com"}, "/d")
	for _, c := range cases {
		c.o.Target = "a.com"
		want := append(slices.Clone(legacy), c.want...)
		if got := Argv(c.o, "/d"); !slices.Equal(got, want) {
			t.Errorf("%s: got %v want %v", c.name, got, want)
		}
	}
}

func TestArgvNeverContainsSecrets(t *testing.T) {
	o := Options{Target: "a.com", Proxy: "http://user:pw-secret@127.0.0.1:8080",
		Headers: []string{"Authorization: Bearer hdr-secret"}, TLS: true}
	for name, a := range map[string][]string{"Argv": Argv(o, "/d"), "PreviewArgv": PreviewArgv(o, "/d")} {
		for _, s := range a {
			if strings.Contains(s, "pw-secret") || strings.Contains(s, "hdr-secret") || strings.Contains(s, "Authorization") || s == "--proxy" || s == "--header" {
				t.Errorf("%s leaked secret: %v", name, a)
			}
		}
	}
	if !slices.Equal(PreviewArgv(o, "/d"), Argv(o, "/d")) {
		t.Error("PreviewArgv differs from Argv")
	}
}

func TestArgvHostileValuesStaySingleArgs(t *testing.T) {
	rule := "a.com; rm -rf / $(x) `y` --evil"
	a := Argv(Options{Target: "a.com", ScopeAllow: []string{rule}, ScopeDeny: []string{"-x y"}}, "/d")
	if !slices.Contains(a, "--scope-allow="+rule) || !slices.Contains(a, "--scope-deny=-x y") {
		t.Errorf("rule not kept as one element: %v", a)
	}
	for _, s := range a {
		if s == "--evil" || s == "-x" {
			t.Errorf("value split into options: %v", a)
		}
	}
}

func TestNotRepresentableFlags(t *testing.T) {
	o := Options{Target: "a.com", Intensity: "active", Findomain: true, Headers: []string{"A: b"}}
	for _, s := range Argv(o, "/d") {
		if s == "--interactive" || s == "--allow-auth" || s == "--brute" || s == "--permute" {
			t.Errorf("forbidden flag %s", s)
		}
	}
}

func TestSpawnEnvFor(t *testing.T) {
	if e := SpawnEnvFor(Options{Target: "a.com"}); len(e) != 0 {
		t.Errorf("no proxy/headers should add nothing, got %v", e)
	}
	p := "http://u:p@127.0.0.1:8080"
	if e := SpawnEnvFor(Options{Proxy: p}); !slices.Equal(e, []string{"BOUNTY_RUN_PROXY=" + p}) {
		t.Errorf("proxy only: %v", e)
	}
	e := SpawnEnvFor(Options{Proxy: p, Headers: []string{"X-A: b\"c", "Y: z"}})
	want := []string{"BOUNTY_RUN_PROXY=" + p, `BOUNTY_RUN_HEADERS=["X-A: b\"c","Y: z"]`}
	if !slices.Equal(e, want) {
		t.Errorf("got %v want %v", e, want)
	}
	if HeadersEnvVar != "BOUNTY_RUN_HEADERS" {
		t.Error("HeadersEnvVar")
	}
}

func TestSpawnDoesNotInheritHeadersEnv(t *testing.T) {
	t.Setenv(HeadersEnvVar, `["Leak: me"]`)
	t.Setenv(ProxyEnvVar, "http://inherited:1")
	dir := t.TempDir()
	bin := writeScript(t, findEvents+`echo "H=[$BOUNTY_RUN_HEADERS] P=[$BOUNTY_RUN_PROXY]" > "$(dirname "$ev")/env.seen"
echo '{"v":1,"t":1,"type":"run_start","target":"a.com"}' >> "$ev"
sleep 5
`)
	o := Options{Target: "a.com"}
	pid, err := SpawnEnv(bin, Argv(o, dir), dir, SpawnEnvFor(o))
	if err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, pid)
	if err := WaitStarted(dir, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "env.seen"))
	// Headers must not leak; the inherited proxy behaviour is unchanged.
	if strings.TrimSpace(string(got)) != "H=[] P=[http://inherited:1]" {
		t.Errorf("child env = %q", got)
	}
}

func TestPresetsMatchExistingTUI(t *testing.T) {
	quick := []string{"subs", "panel", "live", "cf", "origin", "origin_deep", "waf", "dork", "secret", "headers", "cors", "tech"}
	standard := append(slices.Clone(quick), "nmap", "vuln", "content", "api")
	deep := append(slices.Clone(standard), "param", "tls", "nikto", "metis", "headi", "noauth", "amass", "nmap-full")
	want := map[string][]string{"quick": quick, "standard": standard, "deep": deep}
	ps := Presets()
	if len(ps) != 3 {
		t.Fatalf("got %d presets", len(ps))
	}
	for _, p := range ps {
		got := append(slices.Clone(p.Stages), p.Flags...)
		if !slices.Equal(got, want[p.ID]) {
			t.Errorf("%s: got %v want %v", p.ID, got, want[p.ID])
		}
	}
	// Mutating a returned preset must not corrupt the next call.
	ps[0].Stages[0] = "zzz"
	if Presets()[0].Stages[0] != "subs" {
		t.Error("Presets returns shared slices")
	}
}

// maxOptions sets every field Argv can emit.
func maxOptions() Options {
	two := 2
	return Options{Target: "a.com", Amass: true, TLS: true, Nikto: true, Nmap: true, Metis: true, Headi: true, Noauth: true, NmapFull: true,
		Skip: []string{"cf"}, Timeout: 5, MaxParamURLs: 7,
		Intensity: "active", Findomain: true, Resolvers: "/r", DNSRate: 300, NoSubsCache: true, Threads: 9, NoOAST: true,
		ScopeAllow: []string{"a.com"}, ScopeDeny: []string{"-b.a.com"}, ScopeFile: "/s", UserAgent: "-ua",
		RateLimit: 1.5, Retries: &two, VerifyTLS: true, NoEvidence: true, EvidenceUnredacted: true,
		EvidenceMaxBody: 10, MaxHosts: 20, Wordlist: "/w", NucleiSeverity: "high", NucleiC: 4, NucleiTimeout: 60,
		RefreshIPIntel: true, IPIntelOffline: true, NoTrack: true}
}

// engineProbe imports the real parser, checks every emitted flag against it,
// then parses the whole argv. Exit 3 means a third-party dependency listed in
// requirements.txt is not installed; every other failure is a real failure.
// It only builds the parser and parses; it contacts no target.
const engineProbe = `
import re, sys
def third_party():
    names = set()
    for line in open("requirements.txt"):
        m = re.match(r"\s*([A-Za-z0-9_.-]+)", line.split("#")[0])
        if m:
            names.add(m.group(1).lower().replace("-", "_"))
    return names
try:
    from runner.cli import build_parser
except ModuleNotFoundError as e:
    if (e.name or "").split(".")[0].lower() in third_party():
        sys.stderr.write("missing dependency: %s\n" % e.name)
        sys.exit(3)
    raise
parser = build_parser()
argv = sys.argv[1:]
for a in argv:
    if a.startswith("--") and a.split("=", 1)[0] not in parser._option_string_actions:
        sys.stderr.write("unknown flag emitted by Argv: %s\n" % a)
        sys.exit(4)
parser.parse_args(argv)
`

// engineRoot is the repo root; BOUNTY_ENGINE_ROOT overrides it (used to prove
// the test fails against a broken engine copy).
func engineRoot() string {
	if r := os.Getenv("BOUNTY_ENGINE_ROOT"); r != "" {
		return r
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// TestArgvFlagsExistInEngineParser checks every flag Argv can emit against the
// real argparse definition. It skips only without python3 or without the
// engine's third-party dependencies; any other failure fails the test.
func TestArgvFlagsExistInEngineParser(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	cmd := exec.Command(py, append([]string{"-c", engineProbe}, Argv(maxOptions(), "/d")...)...)
	cmd.Dir = engineRoot()
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 3 {
		t.Skipf("engine dependency not installed: %s", out)
	}
	if err != nil {
		t.Fatalf("engine parser check failed: %v\n%s", err, out)
	}
}

func TestOptionsArgvIncludesEngagementIdentity(t *testing.T) {
	got := Argv(Options{Target: "a.com", Client: "acme", Engagement: "ext web", PreparedBy: "me", Team: "STRASSER"}, "/d")
	for _, w := range []string{"--client=acme", "--engagement=ext web", "--prepared-by=me", "--team=STRASSER"} {
		if !slices.Contains(got, w) {
			t.Errorf("argv %v missing %q", got, w)
		}
	}
	for _, a := range Argv(Options{Target: "a.com"}, "/d") {
		if strings.HasPrefix(a, "--client") || strings.HasPrefix(a, "--engagement") || strings.HasPrefix(a, "--prepared-by") || strings.HasPrefix(a, "--team") {
			t.Errorf("empty identity emitted %q", a)
		}
	}
}

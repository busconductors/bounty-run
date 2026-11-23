package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
		{"all", Options{Target: "a.com", Amass: true, TLS: true, Nikto: true, Nmap: true, Metis: true, Headi: true, NmapFull: true,
			Skip: []string{"cf"}, Timeout: 30, MaxParamURLs: 5, Proxy: "http://u:p@h:1"},
			with("--amass", "--tls", "--nikto", "--nmap", "--metis", "--headi", "--nmap-full", "--skip", "cf", "--timeout", "30", "--max-param-urls", "5")},
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
	deep := append(slices.Clone(standard), "param", "tls", "nikto", "metis", "headi", "amass", "nmap-full")
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
	return Options{Target: "a.com", Amass: true, TLS: true, Nikto: true, Nmap: true, Metis: true, Headi: true, NmapFull: true,
		Skip: []string{"cf"}, Timeout: 5, MaxParamURLs: 7,
		Intensity: "active", Findomain: true, Resolvers: "/r", DNSRate: 300, NoSubsCache: true, Threads: 9, NoOAST: true,
		ScopeAllow: []string{"a.com"}, ScopeDeny: []string{"-b.a.com"}, ScopeFile: "/s", UserAgent: "-ua",
		RateLimit: 1.5, Retries: &two, VerifyTLS: true, NoEvidence: true, EvidenceUnredacted: true,
		EvidenceMaxBody: 10, MaxHosts: 20, Wordlist: "/w", NucleiSeverity: "high", NucleiC: 4, NucleiTimeout: 60,
		RefreshIPIntel: true, IPIntelOffline: true, NoTrack: true}
}

// TestArgvFlagsExistInEngineParser checks every flag Argv can emit against the
// real argparse definition. It only builds the parser; it contacts no target.
func TestArgvFlagsExistInEngineParser(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	if _, err := os.Stat(filepath.Join(root, "bounty_run.py")); err != nil {
		t.Skip("bounty_run.py not found")
	}
	cmd := exec.Command(py, "bounty_run.py", "--help")
	cmd.Dir = root
	help, err := cmd.Output()
	if err != nil {
		t.Skipf("engine --help unavailable: %v", err)
	}
	argv := Argv(maxOptions(), "/d")
	known := regexp.MustCompile(`--[a-z][a-z-]*`)
	have := map[string]bool{}
	for _, f := range known.FindAllString(string(help), -1) {
		have[f] = true
	}
	for _, a := range argv {
		if !strings.HasPrefix(a, "--") {
			continue
		}
		flag, _, _ := strings.Cut(a, "=")
		if !have[flag] {
			t.Errorf("Argv emits %s, which the engine parser does not define", flag)
		}
	}
	// Values must also parse (choices, ints, leading '-').
	chk := exec.Command(py, "-c", "import sys; from runner.cli import build_parser; build_parser().parse_args(sys.argv[1:])")
	chk.Dir = root
	chk.Args = append(chk.Args, argv...)
	if out, err := chk.CombinedOutput(); err != nil {
		t.Errorf("engine parser rejected argv: %v\n%s", err, out)
	}
}

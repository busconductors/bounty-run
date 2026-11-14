package engine

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// proxyCases is shared in spirit with tests/test_proxy.py; the parity test
// below also runs every case through the real Python parser.
var proxyCases = []struct {
	in string
	ok bool
}{
	{"http://127.0.0.1:8080", true},
	{"https://proxy.example.com:443", true},
	{"socks5://10.8.0.1:1080", true},
	{"socks5h://user:p%40ss@10.8.0.1:1080", true},
	{"HTTP://LocalHost:3128/", true},
	{"http://[::1]:8080", true},
	{"  http://h:1  ", true},
	{"http://u%3Ax:pw@h:65535", true},
	{"http://u@h:80", true},
	{"127.0.0.1:8080", false},
	{"socks4://h:1080", false},
	{"socks4a://h:1080", false},
	{"ftp://h:21", false},
	{"http://h", false},
	{"http://h:0", false},
	{"http://h:65536", false},
	{"http://h:80a", false},
	{"http://h:1;id", false},
	{"http://h:8080/path", false},
	{"http://h:8080?x=1", false},
	{"http://h:8080#f", false},
	{"http://h :8080", false},
	{"http://:8080", false},
	{"http://bad_host:8080", false},
	{"http://999.1.1.1:8080", false},
	{"http://[::1:8080", false},
	{"http://[1.2.3.4]:8080", false},
	{"http://a@b@h:8080", false},
	{"http://:pw@h:8080", false},
	{"http://us er:pw@h:8080", false},
	{"", false},
}

func TestParseProxyTable(t *testing.T) {
	for _, c := range proxyCases {
		got, err := ParseProxy(c.in)
		if (err == nil) != c.ok {
			t.Errorf("ParseProxy(%q) err = %v, want ok=%v", c.in, err, c.ok)
		}
		if err == nil && got != strings.TrimSpace(c.in) {
			t.Errorf("ParseProxy(%q) = %q", c.in, got)
		}
	}
	if _, err := ParseProxy("127.0.0.1:8080"); err == nil || !strings.Contains(err.Error(), "proxy needs a scheme") {
		t.Errorf("missing-scheme message = %v", err)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "bounty_run.py")); err == nil {
			return root
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("bounty_run.py not found walking up from cwd")
		}
		root = parent
	}
}

// TestParseProxyParity runs the same table through runner/proxy.py parse.
func TestParseProxyParity(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	ins := make([]string, len(proxyCases))
	for i, c := range proxyCases {
		ins[i] = c.in
	}
	b, _ := json.Marshal(ins)
	const script = `import json, sys
from runner import proxy
out = []
for s in json.loads(sys.argv[1]):
    try:
        proxy.parse(s); out.append(True)
    except ValueError:
        out.append(False)
print(json.dumps(out))`
	cmd := exec.Command(py, "-c", script, string(b))
	cmd.Dir = repoRoot(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python3: %v", err)
	}
	var pyOK []bool
	if err := json.Unmarshal(out, &pyOK); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	for i, c := range proxyCases {
		_, gerr := ParseProxy(c.in)
		if (gerr == nil) != pyOK[i] {
			t.Errorf("parity %q: go ok=%v python ok=%v", c.in, gerr == nil, pyOK[i])
		}
	}
}

func TestArgvNeverContainsProxy(t *testing.T) {
	p := "socks5h://user:secret@10.0.0.1:1080"
	a := Argv(Options{Target: "a.com", Proxy: p, TLS: true}, "/d")
	for _, s := range a {
		if strings.Contains(s, "secret") || strings.Contains(s, "10.0.0.1") || s == "--proxy" {
			t.Fatalf("proxy leaked into argv: %v", a)
		}
	}
	if ProxyEnv(Options{Target: "a.com"}) != nil {
		t.Error("ProxyEnv without proxy should be nil")
	}
	if e := ProxyEnv(Options{Proxy: p}); !slices.Equal(e, []string{"BOUNTY_RUN_PROXY=" + p}) {
		t.Errorf("ProxyEnv = %v", e)
	}
}

func TestSpawnEnvPassesProxy(t *testing.T) {
	dir := t.TempDir()
	bin := writeScript(t, findEvents+`echo "$BOUNTY_RUN_PROXY" > "$(dirname "$ev")/proxy.seen"
echo '{"v":1,"t":1,"type":"run_start","target":"a.com"}' >> "$ev"
sleep 5
`)
	o := Options{Target: "a.com", Proxy: "http://u:p@127.0.0.1:8080"}
	pid, err := SpawnEnv(bin, Argv(o, dir), dir, ProxyEnv(o))
	if err != nil {
		t.Fatal(err)
	}
	killOnCleanup(t, pid)
	if err := WaitStarted(dir, 3*time.Second); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "proxy.seen"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != o.Proxy {
		t.Errorf("child BOUNTY_RUN_PROXY = %q", got)
	}
	cmdline, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if strings.Contains(string(cmdline), "u:p@") {
		t.Errorf("proxy in cmdline: %q", cmdline)
	}
}

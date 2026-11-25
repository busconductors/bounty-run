package ui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/busconductors/bounty-run/core/engine"
)

func cannedTools() []engine.Tool {
	return []engine.Tool{
		{Name: "nmap", RequiredBy: []string{"nmap"}, Status: "ok"},
		{Name: "nuclei", RequiredBy: []string{"vuln"}, Status: "missing"},
		{Name: "amass", RequiredBy: []string{"subs"}, Optional: true, Status: "unknown_version"},
	}
}

// newSetupRoot returns a Root on the Setup screen with a canned doctor report.
func newSetupRoot(t *testing.T, tools []engine.Tool) *Root {
	t.Helper()
	r := NewRoot(Config{OutputsRoot: t.TempDir(), EngineBin: "/nonexistent"}).(*Root)
	r.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	r.Update(OpenSetupMsg{})
	r.Update(doctorLoadedMsg{tools: tools})
	if r.Screen() != "setup" {
		t.Fatalf("screen = %q, want setup", r.Screen())
	}
	return r
}

func TestSetupScreenRendersToolStatus(t *testing.T) {
	r := newSetupRoot(t, cannedTools())
	v := r.View().Content
	for _, want := range []string{"nmap", "nuclei", "amass", "missing", "ok", "optional", "vuln"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q:\n%s", want, v)
		}
	}
	if !strings.Contains(v, "✗") || !strings.Contains(v, "✓") {
		t.Errorf("expected status glyphs in view:\n%s", v)
	}
	if !strings.Contains(v, "1 core tool") {
		t.Errorf("missing-core summary absent:\n%s", v)
	}
}

func TestSetupInstalledNeedsPathShownAmber(t *testing.T) {
	// Real path: Config.Doctor (the engine's doctor) reports the status.
	cfg := Config{OutputsRoot: t.TempDir(), EngineBin: "x", Doctor: func(string) ([]engine.Tool, error) {
		return []engine.Tool{
			{Name: "nuclei", Status: "installed_needs_path", Path: "/home/u/go/bin/nuclei"},
			{Name: "nmap", Status: "ok"},
		}, nil
	}}
	r := NewRoot(cfg).(*Root)
	r.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	_, cmd := r.Update(OpenSetupMsg{})
	if cmd == nil {
		t.Fatal("expected doctor load cmd")
	}
	r.Update(cmd())
	v := r.View().Content
	if !strings.Contains(v, "/home/u/go/bin") || !strings.Contains(v, "needs PATH") {
		t.Errorf("needs-path dir not shown:\n%s", v)
	}
	if got := statusStyle("installed_needs_path").GetForeground(); got != colAmber {
		t.Errorf("colour = %v, want amber", got)
	}
	if statusStyle("ok").GetForeground() != colGreen || statusStyle("missing").GetForeground() != colRed {
		t.Error("ok must be green and missing red")
	}
	// An off-PATH core tool is unusable by scans, so it still counts.
	if !strings.Contains(v, "1 core tool") {
		t.Errorf("off-PATH core tool not flagged:\n%s", v)
	}
}

func TestLaunchSoftGateWarnsButProceeds(t *testing.T) {
	r := NewRoot(Config{OutputsRoot: t.TempDir(), EngineBin: "/nonexistent"}).(*Root)
	r.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	r.Update(doctorLoadedMsg{tools: cannedTools()})
	r.Update(NewRunMsg{})
	r.launch.target = "example.com"

	r.Update(launchSubmitMsg{})
	if r.launch.state != launchGate {
		t.Fatalf("state = %v, want launchGate", r.launch.state)
	}
	v := r.View().Content
	if !strings.Contains(v, "nuclei") || !strings.Contains(v, "Proceed anyway") || !strings.Contains(v, "Open Setup") {
		t.Errorf("gate banner incomplete:\n%s", v)
	}
	if strings.Contains(v, "amass") { // optional tools never gate
		t.Errorf("optional tool named in gate:\n%s", v)
	}

	_, cmd := r.Update(tea.KeyPressMsg{Code: 'p', Text: "p"})
	if r.launch.state != launchStarting || cmd == nil {
		t.Fatalf("proceed must start the run: state=%v cmd=%v", r.launch.state, cmd)
	}
}

func TestLaunchGateOpensSetup(t *testing.T) {
	r := NewRoot(Config{OutputsRoot: t.TempDir(), EngineBin: "/nonexistent"}).(*Root)
	r.Update(doctorLoadedMsg{tools: cannedTools()})
	r.Update(NewRunMsg{})
	r.launch.target = "example.com"
	r.Update(launchSubmitMsg{})
	_, cmd := r.Update(tea.KeyPressMsg{Code: 's', Text: "s"})
	if cmd == nil {
		t.Fatal("s should open setup")
	}
	r.Update(cmd())
	if r.Screen() != "setup" {
		t.Errorf("screen = %q, want setup", r.Screen())
	}
}

func TestLaunchGateWarnsForNeedsPath(t *testing.T) {
	r := NewRoot(Config{OutputsRoot: t.TempDir(), EngineBin: "/nonexistent"}).(*Root)
	r.Update(doctorLoadedMsg{tools: []engine.Tool{{Name: "nuclei", Status: "installed_needs_path", Path: "/x/bin/nuclei"}}})
	r.Update(NewRunMsg{})
	r.launch.target = "example.com"
	r.Update(launchSubmitMsg{})
	if r.launch.state != launchGate {
		t.Errorf("state = %v, want launchGate", r.launch.state)
	}
}

func TestLaunchNoGateWhenCoreOK(t *testing.T) {
	r := NewRoot(Config{OutputsRoot: t.TempDir(), EngineBin: "/nonexistent"}).(*Root)
	r.Update(doctorLoadedMsg{tools: []engine.Tool{{Name: "nmap", Status: "ok"}}})
	r.Update(NewRunMsg{})
	r.launch.target = "example.com"
	r.Update(launchSubmitMsg{})
	if r.launch.state != launchStarting {
		t.Errorf("state = %v, want launchStarting", r.launch.state)
	}
}

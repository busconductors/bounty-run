package ui

import (
	"os"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"bountyrun/tui/internal/events"
)

// The embedded copy must match the repo asset (`make banner` syncs it).
func TestEmbeddedBannerMatchesAsset(t *testing.T) {
	want, err := os.ReadFile("../../../assets/startup_banner.txt")
	if err != nil {
		t.Fatal(err)
	}
	if startupBanner != string(want) {
		t.Fatal("tui/internal/ui/assets/startup_banner.txt is stale: run `make banner`")
	}
}

func TestBannerRendersArtUnmodifiedInRed(t *testing.T) {
	v := bannerView()
	p := plain(v)
	for _, l := range bannerLines() {
		if !strings.Contains(p, l) {
			t.Fatalf("banner line altered or missing: %q", l)
		}
	}
	for _, w := range []string{"⣀⣀", "___", "Bounty Runner by busconductors"} {
		if !strings.Contains(p, w) {
			t.Fatalf("missing %q", w)
		}
	}
	if !strings.Contains(v, "38;2;248;81;73") { // #f85149
		t.Fatal("banner not rendered in red")
	}
}

func TestSplashDismissedByKeyOrTimer(t *testing.T) {
	r := NewRoot(Config{OutputsRoot: t.TempDir(), Splash: true}).(*Root)
	if r.Screen() != "splash" {
		t.Fatalf("screen = %s", r.Screen())
	}
	r.Update(tea.WindowSizeMsg{Width: 120, Height: 45})
	if v := plain(r.View().Content); !strings.Contains(v, "Bounty Runner by busconductors") || !strings.Contains(v, "⣀⣀") {
		t.Fatalf("splash missing banner:\n%s", v)
	}
	r.Update(tea.KeyPressMsg{Code: 'x', Text: "x"})
	if r.Screen() != "runs" {
		t.Fatalf("key left screen at %s", r.Screen())
	}
	r2 := NewRoot(Config{OutputsRoot: t.TempDir(), Splash: true}).(*Root)
	r2.Update(splashDoneMsg{})
	if r2.Screen() != "runs" {
		t.Fatalf("timer left screen at %s", r2.Screen())
	}
	// A late timer must not yank the user off another screen.
	r.Update(NewRunMsg{})
	r.Update(splashDoneMsg{})
	if r.Screen() != "launch" {
		t.Fatalf("late timer moved screen to %s", r.Screen())
	}
}

func TestSplashCaptionOnSmallTerminal(t *testing.T) {
	v := plain(splashView(40, 12))
	if !strings.Contains(v, "Bounty Runner by busconductors") {
		t.Fatal(v)
	}
}

func TestLaunchScreenShowsBannerWhenWide(t *testing.T) {
	tm := teatest.NewTestModel(t, NewRoot(Config{OutputsRoot: t.TempDir()}), teatest.WithInitialTermSize(120, 50))
	teatest.WaitFor(t, tm.Output(), contains("Runs"), teatest.WithDuration(5*time.Second))
	tm.Send(tea.KeyPressMsg{Code: 'n', Text: "n"})
	teatest.WaitFor(t, tm.Output(), contains("Target"), teatest.WithDuration(5*time.Second))
	r := finalRoot(t, tm)
	v := r.launch.View()
	if !strings.Contains(plain(v), "Bounty Runner by busconductors") || !strings.Contains(plain(v), "⠉⠛⠲⢤⡀") {
		t.Fatalf("launch screen missing banner:\n%s", plain(v))
	}
	for i, l := range strings.Split(v, "\n") {
		if w := lipgloss.Width(l); w > 120 {
			t.Fatalf("line %d is %d wide", i, w)
		}
	}
	r.launch.width = 80 // too narrow: form only
	if strings.Contains(plain(r.launch.View()), "⠉⠛⠲⢤⡀") {
		t.Fatal("banner shown on a narrow terminal")
	}
}

func TestMonitorFitsTerminalAndColoursSeverity(t *testing.T) {
	mm := NewMonitor("/runs/a", Config{})
	m := &mm
	m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	send := func(ev events.Event) {
		m.Update(tailMsg{gen: m.gen, msgs: []tea.Msg{events.Msg{RunDir: "/runs/a", Ev: ev}}})
	}
	send(events.Event{Type: "run_start", Target: "acme.com", Stages: []string{"subs", "vuln"}})
	send(events.Event{Type: "finding", Severity: "critical", Template: "exposed-git", Host: "h1", URL: "https://h1/x"})
	v := m.render()
	lines := strings.Split(v, "\n")
	if len(lines) > 30 {
		t.Fatalf("%d lines for a 30-line terminal", len(lines))
	}
	for i, l := range lines {
		if w := lipgloss.Width(l); w > 100 {
			t.Fatalf("line %d is %d wide: %q", i, w, plain(l))
		}
	}
	for _, w := range []string{"╭", "Stages", "Output", "Findings", "CRITICAL"} {
		if !strings.Contains(plain(v), w) {
			t.Fatalf("missing %q\n%s", w, plain(v))
		}
	}
	if !strings.Contains(v, "\x1b[38;2;248;81;73mCRITICAL\x1b[39m") {
		t.Fatal("critical finding not red")
	}
}

func TestGlyphColours(t *testing.T) {
	for _, c := range []struct {
		st   string
		want lipgloss.Style
	}{{"ok", okStyle}, {"running", runStyle}, {"failed", badStyle}, {"cancelled", greyStyle}} {
		if _, s := stageGlyph(c.st); s.GetForeground() != c.want.GetForeground() {
			t.Errorf("%s: wrong colour", c.st)
		}
	}
	if sevFg("medium") != colAmber || sevFg("high") != colRed || sevFg("info") != colFaint {
		t.Error("severity palette")
	}
}

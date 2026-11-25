package ui

import (
	"fmt"
	"os/exec"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/busconductors/bounty-run/core/engine"
)

// OpenSetupMsg switches to the Setup/Readiness screen.
type OpenSetupMsg struct{}

// doctorLoadedMsg carries a doctor report (or its error).
type doctorLoadedMsg struct {
	tools []engine.Tool
	err   error
}

// setupResultsMsg carries per-tool install outcomes (from engine.Setup).
type setupResultsMsg struct{ results []engine.SetupResult }

// setupExecDoneMsg reports that a suspended `bounty-run setup` returned.
type setupExecDoneMsg struct{ err error }

// loadDoctor runs the doctor off the Update goroutine. A nil fn uses
// engine.Doctor.
func loadDoctor(cfg Config) tea.Cmd {
	fn := cfg.Doctor
	if fn == nil {
		fn = engine.Doctor
	}
	return func() tea.Msg {
		tools, err := fn(cfg.EngineBin)
		return doctorLoadedMsg{tools: tools, err: err}
	}
}

// missingCore lists the required tools the doctor reports missing.
func missingCore(tools []engine.Tool) []string {
	var out []string
	for _, t := range tools {
		if !t.Optional && t.Status == "missing" {
			out = append(out, t.Name)
		}
	}
	return out
}

// statusStyle: green ok, red missing, amber for anything in between
// (unknown_version, installed_needs_path).
func statusStyle(status string) lipgloss.Style {
	switch status {
	case "ok":
		return okStyle
	case "missing":
		return badStyle
	}
	return warnStyle
}

func statusGlyph(status string) string {
	switch status {
	case "ok":
		return "✓"
	case "missing":
		return "✗"
	}
	return "!"
}

// setupModel is the Setup/Readiness screen: a tool table plus install keys.
type setupModel struct {
	cfg           Config
	tools         []engine.Tool
	notes         map[string]engine.SetupResult
	cursor        int
	loading       bool
	err           string
	width, height int
}

func newSetup(cfg Config, tools []engine.Tool) *setupModel {
	return &setupModel{cfg: cfg, tools: tools, notes: map[string]engine.SetupResult{}}
}

// effective applies install outcomes over the doctor report: a tool installed
// outside PATH shows as installed_needs_path rather than missing.
func (m *setupModel) effective() []engine.Tool {
	out := make([]engine.Tool, len(m.tools))
	copy(out, m.tools)
	for i, t := range out {
		if n, ok := m.notes[t.Name]; ok && n.Outcome == "installed_needs_path" && t.Status == "missing" {
			out[i].Status = "installed_needs_path"
		}
	}
	return out
}

func (m *setupModel) selectedName() string {
	if m.cursor < len(m.tools) {
		return m.tools[m.cursor].Name
	}
	return ""
}

func (m *setupModel) execSetup(args ...string) tea.Cmd {
	c := exec.Command(m.cfg.EngineBin, append([]string{"setup"}, args...)...)
	return tea.ExecProcess(c, func(err error) tea.Msg { return setupExecDoneMsg{err: err} })
}

func (m *setupModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case doctorLoadedMsg:
		m.loading = false
		if msg.err != nil {
			m.err = msg.err.Error()
			return nil
		}
		m.err, m.tools = "", msg.tools
		m.cursor = min(m.cursor, max(len(m.tools)-1, 0))
	case setupResultsMsg:
		for _, r := range msg.results {
			m.notes[r.Name] = r
		}
	case setupExecDoneMsg:
		if msg.err != nil {
			m.err = "setup: " + msg.err.Error()
		}
		m.loading = true
		return loadDoctor(m.cfg) // refresh status after the install
	case tea.KeyPressMsg:
		switch msg.String() {
		case "up", "k":
			m.cursor = max(m.cursor-1, 0)
		case "down", "j":
			m.cursor = min(m.cursor+1, max(len(m.tools)-1, 0))
		case "i", "enter":
			if n := m.selectedName(); n != "" {
				return m.execSetup(n)
			}
		case "a":
			return m.execSetup("--all-core")
		case "r":
			m.loading = true
			return loadDoctor(m.cfg)
		case "esc", "q":
			return func() tea.Msg { return ShowRunsMsg{} }
		case "ctrl+c":
			return tea.Quit
		}
	}
	return nil
}

func (m *setupModel) View() string {
	tools := m.effective()
	var b strings.Builder
	if len(tools) == 0 {
		if m.loading {
			b.WriteString(dimStyle.Render("checking tools…"))
		} else {
			b.WriteString(dimStyle.Render("no tool report yet — press r to check"))
		}
	}
	for i, t := range tools {
		st := statusStyle(t.Status)
		label := t.Status
		if t.Status == "installed_needs_path" {
			label = "installed, needs PATH"
			if d := m.notes[t.Name].Detail; d != "" {
				label += ": " + d
			}
		}
		line := fmt.Sprintf("%s %-14s %s", st.Render(statusGlyph(t.Status)), t.Name, st.Render(label))
		if t.Optional {
			line += " " + greyStyle.Render("(optional)")
		}
		if len(t.RequiredBy) > 0 {
			line += "  " + dimStyle.Render("for "+strings.Join(t.RequiredBy, ", "))
		}
		if i == m.cursor {
			line = cursorStyle.Render("▸") + " " + line
		} else {
			line = "  " + line
		}
		b.WriteString(line + "\n")
	}
	if miss := missingCore(tools); len(miss) > 0 {
		s := "s"
		if len(miss) == 1 {
			s = ""
		}
		b.WriteString("\n" + badStyle.Render(fmt.Sprintf("%d core tool%s missing: %s", len(miss), s, strings.Join(miss, ", "))))
	} else if len(tools) > 0 {
		b.WriteString("\n" + okStyle.Render("all core tools ready"))
	}
	if m.err != "" {
		b.WriteString("\n" + badStyle.Render("✗ "+expandTabs(sanitize(m.err))))
	}
	box := paneBox(true).Render(strings.TrimRight(b.String(), "\n"))
	help := helpBar("i install selected", "a install all core", "r re-check", "esc back")
	return headerBar("Setup", "tool readiness") + "\n" + box + "\n" + help
}

package ui

import (
	"fmt"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"bountyrun/tui/internal/runstore"
)

const maxActive = 3

type runsMsg struct {
	runs []runstore.Run
	err  error
}
type tickMsg struct{}

type runsModel struct {
	root   string
	runs   []runstore.Run
	cursor int
	selDir string // selected run's dir; selection follows it across refreshes
	err    error
	width  int
}

func newRunsModel(root string) *runsModel { return &runsModel{root: root, width: 80} }

func (m *runsModel) load() tea.Cmd {
	root := m.root
	return func() tea.Msg {
		runs, err := runstore.Discover(root)
		return runsMsg{runs, err}
	}
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m *runsModel) Init() tea.Cmd { return tea.Batch(m.load(), tick()) }

func (m *runsModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case runsMsg:
		m.err = msg.err
		if msg.err != nil {
			return nil // keep the previous list
		}
		m.runs = msg.runs
		m.resync()
	case tickMsg:
		return tea.Batch(m.load(), tick())
	case tea.KeyPressMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
				m.selDir = m.runs[m.cursor].Info.Dir
			}
		case "down", "j":
			if m.cursor < len(m.runs)-1 {
				m.cursor++
				m.selDir = m.runs[m.cursor].Info.Dir
			}
		case "enter":
			if m.cursor < len(m.runs) {
				dir := m.runs[m.cursor].Info.Dir
				return func() tea.Msg { return AttachMsg{Dir: dir} }
			}
		case "n":
			return func() tea.Msg { return NewRunMsg{} }
		case "q", "ctrl+c":
			return tea.Quit
		}
	}
	return nil
}

// resync re-finds the selected dir after the list changed, else clamps.
func (m *runsModel) resync() {
	for i, r := range m.runs {
		if r.Info.Dir == m.selDir {
			m.cursor = i
			return
		}
	}
	m.cursor = min(m.cursor, max(0, len(m.runs)-1))
	m.selDir = ""
	if m.cursor < len(m.runs) {
		m.selDir = m.runs[m.cursor].Info.Dir
	}
}

func glyph(s runstore.Status) (string, lipgloss.Style) {
	switch s {
	case runstore.Running:
		return "●", runStyle
	case runstore.OK:
		return "✓", okStyle
	case runstore.Failed, runstore.Crashed:
		return "✗", badStyle
	case runstore.Cancelled:
		return "■", warnStyle
	}
	return "?", dimStyle // incompatible or unknown status
}

func fmtElapsed(d time.Duration) string {
	mins := int(d.Minutes())
	return fmt.Sprintf("%dh%02dm", mins/60, mins%60)
}

func padTo(s string, w int) string {
	if n := lipgloss.Width(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func clip(s string, w int) string {
	r := []rune(s)
	if len(r) > w {
		return string(r[:w-1]) + "…"
	}
	return s
}

func sevCells(sev map[string]int, styled bool) string {
	total := 0
	for _, k := range []string{"critical", "high", "medium", "low"} {
		total += sev[k]
	}
	if total == 0 {
		return padTo("—", 15)
	}
	var parts []string
	for _, c := range []struct{ k, l string }{{"critical", "C"}, {"high", "H"}, {"medium", "M"}, {"low", "L"}} {
		t := fmt.Sprintf("%s%d", c.l, sev[c.k])
		if styled {
			t = sevStyle(c.k).Render(t)
		}
		parts = append(parts, t)
	}
	return padTo(strings.Join(parts, " "), 15)
}

func (m *runsModel) row(r runstore.Run, selected bool) string {
	g, gs := glyph(r.Status)
	stage := r.CurrentStage
	if stage == "" {
		stage = "—"
	}
	rest := fmt.Sprintf(" %s %s %s ", padTo(clip(r.Info.Target, 22), 22),
		padTo(clip(stage, 10), 10), padTo(fmtElapsed(r.Elapsed), 7))
	status := string(r.Status)
	if selected {
		return cursorStyle.Render(g + rest + sevCells(r.Sev, false) + " " + status)
	}
	return gs.Render(g) + rest + sevCells(r.Sev, true) + " " + status
}

func (m *runsModel) View() string {
	active := runstore.ActiveCount(m.runs)
	var b strings.Builder
	b.WriteString(titleStyle.Render("Runs") + "  " +
		dimStyle.Render(fmt.Sprintf("%d/%d active", active, maxActive)) + "\n\n")
	if len(m.runs) == 0 {
		b.WriteString(dimStyle.Render("no runs found in "+m.root) + "\n")
	}
	if m.err != nil {
		b.WriteString(badStyle.Render("error: "+m.err.Error()) + "\n")
	}
	for i, r := range m.runs {
		b.WriteString(m.row(r, i == m.cursor) + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("↑/↓ select · enter attach · n new · q quit"))
	return b.String()
}

package ui

import (
	tea "charm.land/bubbletea/v2"
)

// Config carries startup settings from main.
type Config struct {
	OutputsRoot, EngineBin string
}

// ShowRunsMsg switches to the Runs screen.
type ShowRunsMsg struct{}

// AttachMsg switches to the Monitor screen for a run directory.
type AttachMsg struct{ Dir string }

// NewRunMsg requests the launch form (handled in a later task; ignored for now).
type NewRunMsg struct{}

// Root is the top-level model that routes between screens.
type Root struct {
	cfg           Config
	runs          *runsModel
	monitor       *monitorPlaceholder
	screen        string
	width, height int
}

// NewRoot builds the root model on the Runs screen.
func NewRoot(cfg Config) tea.Model {
	return &Root{cfg: cfg, runs: newRunsModel(cfg.OutputsRoot), screen: "runs"}
}

// Screen returns "runs" or "monitor".
func (r *Root) Screen() string { return r.screen }

func (r *Root) Init() tea.Cmd { return r.runs.Init() }

func (r *Root) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = m.Width, m.Height
		r.runs.width = m.Width
	case ShowRunsMsg:
		r.screen, r.monitor = "runs", nil
		return r, nil
	case AttachMsg:
		r.screen, r.monitor = "monitor", &monitorPlaceholder{dir: m.Dir}
		return r, nil
	case NewRunMsg:
		return r, nil
	}
	switch msg.(type) {
	case runsMsg, tickMsg: // refresh keeps running while attached
		return r, r.runs.Update(msg)
	}
	if r.screen == "monitor" && r.monitor != nil {
		return r, r.monitor.Update(msg)
	}
	return r, r.runs.Update(msg)
}

func (r *Root) View() tea.View {
	var s string
	if r.screen == "monitor" && r.monitor != nil {
		s = r.monitor.View()
	} else {
		s = r.runs.View()
	}
	v := tea.NewView(s)
	v.AltScreen = true
	return v
}

// monitorPlaceholder stands in for the Monitor screen until it is implemented.
type monitorPlaceholder struct{ dir string }

func (m *monitorPlaceholder) Update(msg tea.Msg) tea.Cmd {
	if k, ok := msg.(tea.KeyPressMsg); ok && k.String() == "esc" {
		return func() tea.Msg { return ShowRunsMsg{} }
	}
	return nil
}

func (m *monitorPlaceholder) View() string {
	return "monitor: " + m.dir + "\n\nesc back"
}

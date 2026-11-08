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

// NewRunMsg opens the launch form.
type NewRunMsg struct{}

// Root is the top-level model that routes between screens.
type Root struct {
	cfg           Config
	runs          *runsModel
	monitor       *MonitorModel
	launch        *launchModel
	screen        string
	width, height int
}

// NewRoot builds the root model on the Runs screen.
func NewRoot(cfg Config) tea.Model {
	return &Root{cfg: cfg, runs: newRunsModel(cfg.OutputsRoot), screen: "runs"}
}

// Screen returns "runs", "launch" or "monitor".
func (r *Root) Screen() string { return r.screen }

func (r *Root) Init() tea.Cmd { return r.runs.Init() }

func (r *Root) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		r.width, r.height = m.Width, m.Height
		r.runs.width = m.Width
		if r.monitor != nil {
			r.monitor.update(m)
		}
		if r.launch != nil {
			return r, r.launch.Update(m)
		}
		return r, nil
	case ShowRunsMsg:
		r.closeMonitor()
		r.launch = nil
		r.screen = "runs"
		return r, nil
	case AttachMsg:
		// A fresh model per attach; the previous Tail (if any) is cancelled.
		r.closeMonitor()
		r.launch = nil
		mm := NewMonitor(m.Dir, r.cfg)
		if r.width > 0 && r.height > 0 {
			mm.update(tea.WindowSizeMsg{Width: r.width, Height: r.height})
		}
		r.screen, r.monitor = "monitor", &mm
		return r, r.monitor.Init()
	case NewRunMsg:
		r.closeMonitor()
		r.launch = newLaunch(r.cfg)
		r.launch.width, r.launch.height = r.width, r.height
		r.screen = "launch"
		return r, r.launch.Init()
	}
	switch msg.(type) {
	case runsMsg, tickMsg: // refresh keeps running while attached
		return r, r.runs.Update(msg)
	}
	if r.screen == "monitor" && r.monitor != nil {
		return r, r.monitor.update(msg)
	}
	if r.screen == "launch" && r.launch != nil {
		return r, r.launch.Update(msg)
	}
	return r, r.runs.Update(msg)
}

func (r *Root) View() tea.View {
	var s string
	if r.screen == "monitor" && r.monitor != nil {
		s = r.monitor.render()
	} else if r.screen == "launch" && r.launch != nil {
		s = r.launch.View()
	} else {
		s = r.runs.View()
	}
	v := tea.NewView(s)
	v.AltScreen = true
	return v
}

func (r *Root) closeMonitor() {
	if r.monitor != nil {
		r.monitor.Close()
		r.monitor = nil
	}
}

package ui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const timelineWidth = 34

// layout sizes the sub-components from the terminal size.
func (m *MonitorModel) layout() {
	bodyH := max(m.height-2, 6)
	rw := max(m.width-timelineWidth-3, 30)
	outH := (bodyH - 2) * 3 / 5
	m.vp.SetWidth(rw)
	m.vp.SetHeight(outH)
	m.tbl.SetWidth(rw)
	m.tbl.SetHeight(bodyH - 2 - outH)
	hostW := max(rw-8-22-6, 10)
	m.tbl.SetColumns([]table.Column{{Title: "SEV", Width: 8}, {Title: "TEMPLATE", Width: 22}, {Title: "HOST", Width: hostW}})
}

// View implements tea.Model for standalone use (tests); Root calls render.
func (m *MonitorModel) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	return v
}

func (m *MonitorModel) render() string {
	var body string
	switch {
	case m.incompatible:
		body = "\n" + badStyle.Render("run produced by incompatible engine version") + "\n"
	case m.detail:
		body = m.detailView()
	default:
		body = m.bodyView()
	}
	var b strings.Builder
	b.WriteString(m.header() + "\n")
	b.WriteString(body + "\n")
	if m.status != "" {
		b.WriteString(badStyle.Render(m.status) + "\n")
	}
	b.WriteString(m.footerLine())
	return b.String()
}

func (m *MonitorModel) header() string {
	name := m.target
	if name == "" {
		name = sanitize(m.dir)
	}
	var state string
	var d time.Duration
	if m.ended {
		state = "finished: " + m.endStatus
		d = time.Duration(m.lastT-m.startT) * time.Millisecond
	} else if m.killed {
		state = "killed"
		if m.startT > 0 {
			d = m.killedAt.Sub(time.UnixMilli(m.startT))
		}
	} else {
		state = "running"
		if m.startT > 0 {
			d = time.Since(time.UnixMilli(m.startT))
		}
	}
	h := titleStyle.Render(name) + " ─ " + state + " " + fmtElapsed(max(d, 0))
	if m.endErr != "" {
		h += "  " + badStyle.Render("error: "+clip(m.endErr, max(m.width-lipgloss.Width(h)-10, 10)))
	}
	return h
}

// footerLine shows a pending y/n prompt or the hard-kill banner in place of
// the key help.
func (m *MonitorModel) footerLine() string {
	switch {
	case m.confirm == "skip":
		return warnStyle.Render("skip " + m.confirmStage + "? y/n")
	case m.confirm == "cancel":
		return warnStyle.Render("cancel run? y/n")
	case m.hardKill:
		return badStyle.Render("engine not responding — K to hard kill")
	}
	return dimStyle.Render(m.footer())
}

func (m *MonitorModel) footer() string {
	switch {
	case m.incompatible:
		return "esc back"
	case m.detail:
		return "esc close · q back"
	}
	f := "tab focus · f filter · enter detail · esc back"
	if m.controllable() {
		f += " · s skip · c cancel"
	}
	if m.ended && m.report != "" {
		f += " · o report"
	}
	return f
}

func stageGlyph(status string) (string, lipgloss.Style) {
	switch status {
	case "ok":
		return "✓", okStyle
	case "running":
		return "▶", runStyle
	case "failed", "cancelled":
		return "✗", badStyle
	case "skipped":
		return "⏭", warnStyle
	}
	return "·", dimStyle
}

func (m *MonitorModel) stageLine(s stageState) string {
	g, gs := stageGlyph(s.status)
	line := gs.Render(g) + " " + padTo(clip(s.id, 12), 12) + " "
	switch s.status {
	case "running":
		if s.total > 0 {
			pct := float64(s.done) / float64(s.total)
			line += fmt.Sprintf("%d/%d ", s.done, s.total) + m.bar.ViewAs(min(pct, 1))
		}
	case "ok":
		if len(s.counts) > 0 {
			n := 0
			for _, c := range s.counts {
				n += c
			}
			line += fmt.Sprintf("%d", n)
		}
	default:
		if s.reason != "" {
			line += dimStyle.Render(clip(s.reason, timelineWidth-16))
		}
	}
	return line
}

func (m *MonitorModel) bodyView() string {
	bodyH := max(m.height-2, 6)
	if m.status != "" {
		bodyH--
	}
	var left []string
	for _, s := range m.stages {
		left = append(left, m.stageLine(s))
	}
	leftCol := lipgloss.NewStyle().Width(timelineWidth).MaxWidth(timelineWidth).
		Height(bodyH).MaxHeight(bodyH).Render(strings.Join(left, "\n"))
	sep := strings.TrimSuffix(strings.Repeat(" │ \n", bodyH), "\n")

	outTitle, findTitle := "Output", fmt.Sprintf("Findings (filter: %s) %d/%d",
		sevFilters[m.filter], len(m.visible), len(m.findings))
	if m.focus == paneOutput {
		outTitle = titleStyle.Render(outTitle)
		findTitle = dimStyle.Render(findTitle)
	} else {
		outTitle = dimStyle.Render(outTitle)
		findTitle = titleStyle.Render(findTitle)
	}
	rw := max(m.width-timelineWidth-3, 30)
	right := lipgloss.NewStyle().MaxWidth(rw).Height(bodyH).MaxHeight(bodyH).Render(
		lipgloss.JoinVertical(lipgloss.Left, outTitle, m.vp.View(), findTitle, m.tbl.View()))
	return lipgloss.JoinHorizontal(lipgloss.Top, leftCol, sep, right)
}

func (m *MonitorModel) detailView() string {
	f, ok := m.selected()
	if !ok {
		return ""
	}
	w := min(max(m.width-4, 20), 100)
	field := func(k, v string) string { return titleStyle.Render(padTo(k, 10)) + v }
	content := strings.Join([]string{
		field("Severity", sevStyle(f.severity).Render(strings.ToUpper(f.severity))),
		field("Template", f.template),
		field("Host", f.host),
		field("URL", f.url),
		field("Summary", f.summary),
	}, "\n")
	return lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Width(w).Render(content)
}

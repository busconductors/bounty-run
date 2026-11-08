package ui

import (
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/table"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const timelineWidth = 34

// Pane chrome: a rounded border plus one cell of padding each side.
const (
	paneChromeW = 4
	paneChromeH = 2
)

// bodyHeight is the pane area: the terminal minus header, status and footer
// lines (the status line is always reserved so the panes never jump).
func (m *MonitorModel) bodyHeight() int { return max(m.height-3, 12) }

// rightInnerWidth is the Output/Findings content width.
func (m *MonitorModel) rightInnerWidth() int {
	return max(m.width-(timelineWidth+paneChromeW), 34) - paneChromeW
}

// layout sizes the sub-components from the terminal size.
func (m *MonitorModel) layout() {
	inner := m.bodyHeight() - 2*paneChromeH - 2 // two boxes, one title line each
	rw := m.rightInnerWidth()
	outH := inner * 3 / 5
	m.vp.SetWidth(rw)
	m.vp.SetHeight(outH)
	m.tbl.SetWidth(rw)
	m.tbl.SetHeight(inner - outH)
	hostW := max(rw-8-22-6, 10)
	m.tbl.SetColumns([]table.Column{{Title: "SEV", Width: 8}, {Title: "TEMPLATE", Width: 22}, {Title: "HOST", Width: hostW}})
	st := table.DefaultStyles()
	st.Header = st.Header.Foreground(colMuted).BorderStyle(lipgloss.NormalBorder()).
		BorderBottom(true).BorderForeground(colBorder)
	st.Selected = lipgloss.NewStyle().Bold(true).Foreground(colText).Background(colPanel)
	m.tbl.SetStyles(st)
	m.bar = progress.New(progress.WithoutPercentage(), progress.WithWidth(10),
		progress.WithColors(colAmber, colRed))
	m.bar.EmptyColor = colBorder
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
		b.WriteString(badStyle.Render("✗ "+m.status) + "\n")
	} else if !m.incompatible && !m.detail {
		b.WriteString("\n") // reserved status line (see bodyHeight)
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
	stStyle := runStyle
	var d time.Duration
	if m.ended {
		state = "finished: " + m.endStatus
		switch m.endStatus {
		case "ok":
			stStyle = okStyle
		case "cancelled":
			stStyle = greyStyle
		default:
			stStyle = badStyle
		}
		d = time.Duration(m.lastT-m.startT) * time.Millisecond
	} else if m.killed {
		state, stStyle = "killed", badStyle
		if m.startT > 0 {
			d = m.killedAt.Sub(time.UnixMilli(m.startT))
		}
	} else if m.crashed {
		state, stStyle = "crashed", badStyle // frozen at the engine's last sign of life
		if m.startT > 0 {
			d = time.Duration(m.lastT-m.startT) * time.Millisecond
		}
	} else {
		state = "running"
		if m.startT > 0 {
			d = time.Since(time.UnixMilli(m.startT))
		}
	}
	h := badgeStyle.Render("BOUNTY RUN") + " " + titleStyle.Render(name) + greyStyle.Render(" ─ ") +
		stStyle.Bold(true).Render(state) + " " + dimStyle.Render(fmtElapsed(max(d, 0)))
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
		return warnStyle.Bold(true).Render("skip " + m.confirmStage + "? y/n")
	case m.confirm == "cancel":
		return warnStyle.Bold(true).Render("cancel run? y/n")
	case m.hardKill:
		return badStyle.Bold(true).Render("engine not responding — K to hard kill")
	}
	return helpBar(strings.Split(m.footer(), " · ")...)
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
	case "failed":
		return "✗", badStyle
	case "cancelled":
		return "✗", greyStyle
	case "skipped":
		return "⏭", greyStyle
	}
	return "·", dimStyle
}

func (m *MonitorModel) stageLine(s stageState) string {
	g, gs := stageGlyph(s.status)
	id := padTo(clip(s.id, 12), 12)
	if s.status == "running" {
		id = titleStyle.Render(id)
	} else if s.status == "" || s.status == "pending" {
		id = dimStyle.Render(id)
	}
	line := gs.Render(g) + " " + id + " "
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
			line += okStyle.Render(fmt.Sprintf("%d", n))
		}
	default:
		if s.reason != "" {
			line += dimStyle.Render(clip(s.reason, timelineWidth-16))
		}
	}
	return line
}

func (m *MonitorModel) bodyView() string {
	bodyH := m.bodyHeight()
	var left []string
	for _, s := range m.stages {
		left = append(left, m.stageLine(s))
	}
	if room := bodyH - paneChromeH - 1; len(left) > room { // keep the bottom border
		left = left[:max(room, 0)]
	}
	timeline := titleStyle.Render("Stages") + "\n" + strings.Join(left, "\n")
	leftCol := paneBox(false).Width(timelineWidth + paneChromeW).Height(bodyH).MaxHeight(bodyH).
		Render(lipgloss.NewStyle().MaxWidth(timelineWidth).Render(timeline))

	outFocus := m.focus == paneOutput
	paneTitle := func(t string, focused bool) string {
		if focused {
			return accentStyle.Render(t)
		}
		return dimStyle.Render(t)
	}
	filter := fmt.Sprintf("filter: %s", sevFilters[m.filter])
	findTitle := paneTitle("Findings", !outFocus) + " " + dimStyle.Render("("+filter+")") + " " +
		dimStyle.Render(fmt.Sprintf("%d/%d", len(m.visible), len(m.findings)))
	rw := m.rightInnerWidth() + paneChromeW
	inner := lipgloss.NewStyle().MaxWidth(rw - paneChromeW)
	outBox := paneBox(outFocus).Width(rw).Render(
		inner.Render(paneTitle("Output", outFocus) + "\n" + m.vp.View()))
	findBox := paneBox(!outFocus).Width(rw).Render(
		inner.Render(findTitle + "\n" + m.tbl.View()))
	right := lipgloss.NewStyle().MaxHeight(bodyH).Render(lipgloss.JoinVertical(lipgloss.Left, outBox, findBox))
	return lipgloss.JoinHorizontal(lipgloss.Top, leftCol, right)
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
	return paneBox(true).Width(w).Render(accentStyle.Render("Finding") + "\n\n" + content)
}

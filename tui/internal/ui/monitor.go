package ui

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"charm.land/bubbles/v2/progress"
	"charm.land/bubbles/v2/table"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"

	"bountyrun/tui/internal/engine"
	"bountyrun/tui/internal/events"
	"bountyrun/tui/internal/runstore"
)

// tailBatchMax caps how many queued tail messages one Update applies, so a
// long replay refreshes the output pane once per batch instead of per line.
const tailBatchMax = 256

var attachGen atomic.Uint64

// tailMsg carries messages from one attach's Tail goroutine. gen identifies
// the attach so messages from an earlier attach are dropped.
type tailMsg struct {
	gen  uint64
	msgs []tea.Msg
}

type pagerDoneMsg struct{ err error }

// defaultControlTimeout is how long a skip/cancel may go unacknowledged before
// the Monitor offers a hard kill.
const defaultControlTimeout = 10 * time.Second

// pendingAck is the newest skip/cancel still waiting for its matching event:
// stage_end for the skipped stage, or run_end for a cancel.
type pendingAck struct {
	kind, stage string // kind is "skip" or "cancel"
	seq         int
}

// ackTimeoutMsg fires controlTimeout after command seq was sent.
type ackTimeoutMsg struct {
	gen uint64
	seq int
}

// controlDoneMsg reports the result of a control write (seq > 0) or hard kill (seq 0).
type controlDoneMsg struct {
	gen uint64
	seq int
	err error
}

type pane int

const (
	paneOutput pane = iota
	paneFindings
)

var sevFilters = []string{"all", "critical", "high", "medium", "low", "info"}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func rank(sev string) int {
	if r, ok := sevRank[sev]; ok {
		return r
	}
	return len(sevRank)
}

type stageState struct {
	id, status, reason string
	counts             map[string]int
	done, total        int
}

type finding struct{ severity, template, host, url, summary string }

// MonitorModel is the read-only Monitor screen for one run directory. Its
// state is built only from that run's events.jsonl.
type MonitorModel struct {
	dir, path string
	cfg       Config
	gen       uint64

	ctx      context.Context
	cancel   context.CancelFunc
	ch       chan tea.Msg
	tailDone chan struct{}

	target         string
	startT, lastT  int64
	stages         []stageState
	out            ring
	findings       []finding // sorted by severity rank, stable
	visible        []int     // indices into findings after the filter
	filter         int
	ended          bool
	endStatus      string
	endErr, report string
	incompatible   bool
	status         string // transient note (pager errors)

	controlTimeout time.Duration // ack deadline; tests shorten it
	confirm        string        // "skip" or "cancel" while a y/n prompt is shown
	confirmStage   string
	pending        *pendingAck
	ctlSeq         int
	hardKill       bool      // "engine not responding" banner shown; K accepted
	killed         bool      // hard kill succeeded; no run_end will follow
	killedAt       time.Time // freezes the elapsed timer

	focus         pane
	detail        bool
	width, height int
	vp            viewport.Model
	tbl           table.Model
	bar           progress.Model
}

// NewMonitor builds a Monitor for dir. Call Init (on the stored pointer) to
// start tailing.
func NewMonitor(dir string, cfg Config) MonitorModel {
	m := MonitorModel{
		dir: dir, path: filepath.Join(dir, "events.jsonl"), cfg: cfg,
		gen:            attachGen.Add(1),
		controlTimeout: defaultControlTimeout,
		width:          100, height: 30,
		vp:  viewport.New(),
		tbl: table.New(),
		bar: progress.New(progress.WithoutPercentage(), progress.WithWidth(10)),
	}
	m.tbl.Blur()
	m.layout()
	return m
}

// Init starts one Tail goroutine for this attach and waits for its messages.
func (m *MonitorModel) Init() tea.Cmd {
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.ch = make(chan tea.Msg, tailBatchMax)
	m.tailDone = make(chan struct{})
	ctx, path, ch, done := m.ctx, m.path, m.ch, m.tailDone
	go func() {
		defer close(done)
		events.Tail(ctx, path, ch)
	}()
	return m.wait()
}

// Close cancels the Tail goroutine. Safe to call more than once or before Init.
func (m *MonitorModel) Close() {
	if m.cancel != nil {
		m.cancel()
	}
}

// wait blocks for the next message, then drains whatever else is queued.
func (m *MonitorModel) wait() tea.Cmd {
	ctx, ch, gen := m.ctx, m.ch, m.gen
	if ctx == nil {
		return nil
	}
	return func() tea.Msg {
		var batch []tea.Msg
		select {
		case <-ctx.Done():
			return nil
		case msg := <-ch:
			batch = append(batch, msg)
		}
		for len(batch) < tailBatchMax {
			select {
			case msg := <-ch:
				batch = append(batch, msg)
			default:
				return tailMsg{gen: gen, msgs: batch}
			}
		}
		return tailMsg{gen: gen, msgs: batch}
	}
}

// Update implements tea.Model; Root uses the returned command only.
func (m *MonitorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, m.update(msg)
}

func (m *MonitorModel) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tailMsg:
		if msg.gen != m.gen {
			return nil // from an earlier attach
		}
		for _, x := range msg.msgs {
			m.apply(x)
		}
		m.refreshOutput()
		m.refreshFindings()
		return m.wait()
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
	case pagerDoneMsg:
		m.status = ""
		if msg.err != nil {
			m.status = "pager: " + sanitize(msg.err.Error())
		}
	case ackTimeoutMsg:
		if msg.gen == m.gen && m.pending != nil && m.pending.seq == msg.seq && !m.ended {
			m.hardKill = true
		}
	case controlDoneMsg:
		if msg.gen != m.gen {
			return nil
		}
		if msg.seq == 0 { // hard kill
			if msg.err != nil {
				m.status = "hard kill: " + sanitize(msg.err.Error())
				m.hardKill = !m.ended // keep the banner so K can be retried
				return nil
			}
			m.status = "hard kill sent"
			m.killed, m.killedAt = true, time.Now()
			m.pending, m.hardKill, m.confirm = nil, false, ""
			return nil
		}
		if msg.err != nil {
			m.status = "control: " + sanitize(msg.err.Error())
			if m.pending != nil && m.pending.seq == msg.seq {
				m.pending, m.hardKill = nil, false
			}
		}
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return nil
}

func (m *MonitorModel) key(k tea.KeyPressMsg) tea.Cmd {
	switch k.String() {
	case "ctrl+c":
		m.Close()
		return tea.Quit
	}
	if m.confirm != "" {
		if k.String() == "y" {
			return m.sendControl()
		}
		m.confirm = "" // any other key declines
		return nil
	}
	if k.String() == "K" {
		if m.hardKill && !m.ended && !m.killed {
			m.hardKill = false
			return m.hardKillCmd()
		}
		return nil
	}
	switch k.String() {
	case "esc":
		if m.detail {
			m.detail = false
			return nil
		}
		return m.detach()
	case "q":
		return m.detach()
	}
	if m.detail || m.incompatible {
		return nil
	}
	switch k.String() {
	case "tab":
		if m.focus == paneOutput {
			m.focus = paneFindings
			m.tbl.Focus()
		} else {
			m.focus = paneOutput
			m.tbl.Blur()
		}
		return nil
	case "f":
		m.filter = (m.filter + 1) % len(sevFilters)
		m.tbl.SetCursor(0)
		m.refreshFindings()
		return nil
	case "enter":
		if len(m.visible) > 0 {
			m.detail = true
		}
		return nil
	case "o":
		return m.openReport()
	case "s":
		if st := m.currentStage(); st != "" && m.controllable() {
			m.confirm, m.confirmStage = "skip", st
		}
		return nil
	case "c":
		if m.controllable() {
			m.confirm = "cancel"
		}
		return nil
	}
	var cmd tea.Cmd
	if m.focus == paneFindings {
		m.tbl, cmd = m.tbl.Update(k)
	} else {
		m.vp, cmd = m.vp.Update(k)
	}
	return cmd
}

// controllable reports whether skip/cancel may be offered.
func (m *MonitorModel) controllable() bool { return !m.ended && !m.killed }

// currentStage is the most recently listed stage that is running.
func (m *MonitorModel) currentStage() string {
	for i := len(m.stages) - 1; i >= 0; i-- {
		if m.stages[i].status == "running" {
			return m.stages[i].id
		}
	}
	return ""
}

// sendControl writes the confirmed command and starts its ack timer. A newer
// command replaces any pending one, so only its timer can raise the banner.
func (m *MonitorModel) sendControl() tea.Cmd {
	kind, stage := m.confirm, m.confirmStage
	m.confirm = ""
	m.ctlSeq++
	seq, gen, dir := m.ctlSeq, m.gen, m.dir
	m.pending = &pendingAck{kind: kind, stage: stage, seq: seq}
	m.hardKill = false
	write := func() tea.Msg {
		var err error
		if kind == "skip" {
			err = engine.Skip(dir, stage)
		} else {
			err = engine.Cancel(dir)
		}
		return controlDoneMsg{gen: gen, seq: seq, err: err}
	}
	timer := tea.Tick(m.controlTimeout, func(time.Time) tea.Msg { return ackTimeoutMsg{gen: gen, seq: seq} })
	return tea.Batch(write, timer)
}

// hardKillCmd reads run.json from disk and SIGKILLs the engine and tool groups.
func (m *MonitorModel) hardKillCmd() tea.Cmd {
	dir, gen := m.dir, m.gen
	return func() tea.Msg {
		info, err := runstore.ReadInfo(dir)
		if err != nil {
			return controlDoneMsg{gen: gen, err: err}
		}
		return controlDoneMsg{gen: gen, err: engine.HardKill(info, dir)}
	}
}

// detach stops tailing and returns to Runs; the run itself is untouched.
func (m *MonitorModel) detach() tea.Cmd {
	m.Close()
	return func() tea.Msg { return ShowRunsMsg{} }
}

func (m *MonitorModel) openReport() tea.Cmd {
	if !m.ended || m.report == "" {
		return nil
	}
	pager := strings.Fields(os.Getenv("PAGER"))
	if len(pager) == 0 {
		pager = []string{"less"}
	}
	c := exec.Command(pager[0], append(pager[1:], m.report)...)
	return tea.ExecProcess(c, func(err error) tea.Msg { return pagerDoneMsg{err} })
}

// apply folds one tail message into the model state.
func (m *MonitorModel) apply(msg tea.Msg) {
	switch msg := msg.(type) {
	case events.VersionMsg:
		if filepath.Clean(msg.RunDir) == filepath.Clean(m.dir) {
			m.incompatible = true
		}
	case events.WarnMsg:
		if filepath.Clean(msg.RunDir) == filepath.Clean(m.dir) {
			m.out.Push("[warn] " + sanitize(msg.Text))
		}
	case events.Msg:
		if filepath.Clean(msg.RunDir) == filepath.Clean(m.dir) {
			m.applyEvent(msg.Ev)
		}
	}
}

func (m *MonitorModel) stage(id string) *stageState {
	for i := range m.stages {
		if m.stages[i].id == id {
			return &m.stages[i]
		}
	}
	m.stages = append(m.stages, stageState{id: id, status: "pending"})
	return &m.stages[len(m.stages)-1]
}

func (m *MonitorModel) applyEvent(ev events.Event) {
	if ev.T > m.lastT {
		m.lastT = ev.T
	}
	switch ev.Type {
	case "run_start":
		m.target, m.startT = sanitize(ev.Target), ev.T
		for _, id := range ev.Stages {
			m.stage(sanitize(id))
		}
	case "stage_start":
		m.stage(sanitize(ev.Stage)).status = "running"
	case "progress":
		s := m.stage(sanitize(ev.Stage))
		s.done, s.total = ev.Done, ev.Total
	case "stage_end":
		s := m.stage(sanitize(ev.Stage))
		s.status, s.reason, s.counts = sanitize(ev.Status), sanitize(ev.Reason), ev.Counts
		if m.pending != nil && m.pending.kind == "skip" && m.pending.stage == s.id {
			m.pending, m.hardKill = nil, false
		}
		if m.confirm == "skip" && m.confirmStage == s.id {
			m.confirm = "" // the stage ended before the user answered
		}
	case "output":
		m.out.Push("[" + sanitize(ev.Tool) + "] " + expandTabs(sanitize(ev.Line)))
	case "log":
		m.out.Push("[" + sanitize(ev.Level) + "] " + expandTabs(sanitize(ev.Msg)))
	case "finding":
		m.findings = append(m.findings, finding{
			severity: sanitize(ev.Severity), template: sanitize(ev.Template),
			host: sanitize(ev.Host), url: sanitize(ev.URL), summary: sanitize(ev.Summary),
		})
		sort.SliceStable(m.findings, func(i, j int) bool {
			return rank(m.findings[i].severity) < rank(m.findings[j].severity)
		})
	case "run_end":
		m.ended = true
		m.pending, m.hardKill, m.confirm = nil, false, ""
		m.endStatus, m.endErr, m.report = sanitize(ev.Status), sanitize(ev.Error), ev.Report
	}
}

func expandTabs(s string) string { return strings.ReplaceAll(s, "\t", "    ") }

// refreshOutput reloads the viewport, following the bottom unless the user
// scrolled up.
func (m *MonitorModel) refreshOutput() {
	follow := m.vp.AtBottom()
	m.vp.SetContentLines(m.out.Lines())
	if follow {
		m.vp.GotoBottom()
	}
}

func (m *MonitorModel) refreshFindings() {
	want := sevFilters[m.filter]
	m.visible = m.visible[:0]
	rows := []table.Row{}
	for i, f := range m.findings {
		if want != "all" && f.severity != want {
			continue
		}
		m.visible = append(m.visible, i)
		rows = append(rows, table.Row{strings.ToUpper(f.severity), f.template, f.host})
	}
	m.tbl.SetRows(rows)
	if len(rows) > 0 && m.tbl.Cursor() < 0 {
		m.tbl.SetCursor(0) // SetRows leaves the cursor at -1 after an empty list
	}
}

// selected returns the finding under the table cursor.
func (m *MonitorModel) selected() (finding, bool) {
	c := m.tbl.Cursor()
	if c < 0 || c >= len(m.visible) {
		return finding{}, false
	}
	return m.findings[m.visible[c]], true
}

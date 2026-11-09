package ui

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"

	"bountyrun/tui/internal/engine"
	"bountyrun/tui/internal/runstore"
)

// launchWait is how long a launch waits for run_start before showing engine.log.
const launchWait = 3 * time.Second

const capError = "3 runs already active — wait or cancel one"

// stageIDs mirrors runner/cli.py STAGE_IDS (pipeline order, same names as --skip).
var stageIDs = []string{"subs", "panel", "live", "cf", "origin", "nmap", "waf", "dork", "tls", "nikto",
	"vuln", "content", "api", "param", "secret", "metis", "headers", "cors", "tech", "headi"}

// stageToggle is one row of the Custom list: an engine stage, a sub-step
// (origin_deep, a --skip token) or a modifier flag (amass, nmap-full).
type stageToggle struct{ id, hint string }

// toggles is the Custom list, in pipeline order. Every id is a --skip token,
// an opt-in flag of the same name, or both (cli.py OPT_IN_STAGES).
var toggles = []stageToggle{
	{"subs", "subdomain enum · passive"},
	{"amass", "+ amass · needs API keys"},
	{"panel", "admin/login panel detection"},
	{"live", "live host probe"},
	{"cf", "Cloudflare detection"},
	{"origin", "origin IP hunt behind CF"},
	{"origin_deep", "extended origin hunt"},
	{"nmap", "nmap top-1000 · intrusive"},
	{"nmap-full", "all 65535 ports · multi-hour"},
	{"waf", "WAF fingerprint"},
	{"dork", "search dorks · passive"},
	{"tls", "sslyze · ~1 min/host"},
	{"nikto", "~5 min/host · intrusive"},
	{"vuln", "nuclei templates · active"},
	{"content", "ffuf content discovery"},
	{"api", "katana crawl · API endpoints"},
	{"param", "sqlmap on params · intrusive"},
	{"secret", "secret / JS leak scan"},
	{"metis", "Metis CVE autocheck"},
	{"headers", "security headers"},
	{"cors", "CORS misconfig"},
	{"tech", "tech fingerprint"},
	{"headi", "169 req/URL · intrusive"},
}

// optInFlags are toggles that turn on an engine flag instead of being skipped
// when off; the engine leaves them off by default.
var optInFlags = map[string]bool{"amass": true, "nmap-full": true, "nmap": true, "tls": true,
	"nikto": true, "metis": true, "headi": true}

type preset struct {
	id, label, desc string
	on              []string // enabled toggles; nil for Custom
}

var (
	quickOn    = []string{"subs", "panel", "live", "cf", "origin", "origin_deep", "waf", "dork", "secret", "headers", "cors", "tech"}
	standardOn = append(slices.Clone(quickOn), "nmap", "vuln", "content", "api")
	deepOn     = append(slices.Clone(standardOn), "param", "tls", "nikto", "metis", "headi", "amass", "nmap-full")
)

const presetDefault = "standard"

var presets = []preset{
	{"quick", "Quick     ~5 min", "~5 min · light/passive: subs, panels, live hosts, CF + origin, WAF, dorks, secrets, headers, CORS, tech", quickOn},
	{"standard", "Standard  ~20-30 min", "~20-30 min · Quick + nmap top-1000, nuclei, ffuf, katana", standardOn},
	{"deep", "Deep      hours", "hours · active/intrusive: Standard + sqlmap, sslyze, nikto, metis, headi, amass, nmap all ports", deepOn},
	{"custom", "Custom", "pick stages one by one on the next page", nil},
}

func presetByID(id string) preset {
	for _, p := range presets {
		if p.id == id {
			return p
		}
	}
	return presets[1]
}

// applyToggles turns a set of enabled toggles into engine options: an enabled
// opt-in sets its flag, a disabled stage becomes a --skip token.
func applyToggles(o *engine.Options, on []string) {
	enabled := func(id string) bool { return slices.Contains(on, id) }
	o.Amass, o.Nmap, o.NmapFull = enabled("amass"), enabled("nmap"), enabled("nmap-full")
	o.TLS, o.Nikto, o.Metis, o.Headi = enabled("tls"), enabled("nikto"), enabled("metis"), enabled("headi")
	o.Skip = nil
	for _, t := range toggles {
		if !optInFlags[t.id] && !enabled(t.id) {
			o.Skip = append(o.Skip, t.id)
		}
	}
}

type launchState int

const (
	launchEditing launchState = iota
	launchStarting
	launchFailed
)

// launchSubmitMsg is sent by the form when the last field is confirmed.
type launchSubmitMsg struct{}

// launchResultMsg reports a launch that did not attach.
type launchResultMsg struct {
	capped bool
	err    error
}

// launchModel is the New run screen: a huh form, then a detached spawn.
type launchModel struct {
	cfg  Config
	form *huh.Form

	// Form values; the fields are bound by pointer so a rebuilt form keeps them.
	target, preset, timeout, maxParam string
	custom                            []string // enabled toggles when preset is Custom

	state         launchState
	inlineErr     string
	failure       []string // sanitized error lines for the failure view
	width, height int
}

func newLaunch(cfg Config) *launchModel {
	l := &launchModel{cfg: cfg, preset: presetDefault, custom: slices.Clone(standardOn)}
	l.form = l.buildForm()
	return l
}

func validTarget(s string) error {
	if _, err := engine.NormalizeTarget(s); err != nil {
		return errors.New("not a valid domain")
	}
	return nil
}

// posInt accepts "" (engine default) or a positive integer.
func posInt(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if n, err := strconv.Atoi(s); err != nil || n <= 0 {
		return errors.New("must be a positive integer")
	}
	return nil
}

func (l *launchModel) buildForm() *huh.Form {
	presetOpts := make([]huh.Option[string], len(presets))
	for i, p := range presets {
		presetOpts[i] = huh.NewOption(p.label, p.id)
	}
	toggleOpts := make([]huh.Option[string], len(toggles))
	for i, t := range toggles {
		toggleOpts[i] = huh.NewOption(fmt.Sprintf("%-11s %s", t.id, dimStyle.Render(t.hint)), t.id)
	}
	f := huh.NewForm(
		huh.NewGroup(
			huh.NewInput().Title("Target").Placeholder("example.com").
				Value(&l.target).Validate(validTarget),
			huh.NewSelect[string]().Title("Preset").Options(presetOpts...).Value(&l.preset).
				DescriptionFunc(func() string { return presetByID(l.preset).desc }, &l.preset),
			huh.NewInput().Title("HTTP timeout (s)").Placeholder("default").
				Value(&l.timeout).Validate(posInt),
			huh.NewInput().Title("Max param URLs").Placeholder("default").
				Value(&l.maxParam).Validate(posInt),
		),
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title("Custom stages").Description("[•] runs · [ ] skipped").
				Options(toggleOpts...).Value(&l.custom).Filterable(false).Height(14),
		).WithHideFunc(func() bool { return l.preset != "custom" }),
	).WithShowHelp(true).WithTheme(huh.ThemeFunc(formTheme))
	f.SubmitCmd = func() tea.Msg { return launchSubmitMsg{} }
	f.CancelCmd = nil
	return f
}

// Init starts the form (and sizes it if the terminal size is already known).
func (l *launchModel) Init() tea.Cmd {
	cmd := l.form.Init()
	if l.width > 0 {
		_, c := l.form.Update(l.formSize())
		cmd = tea.Batch(cmd, c)
	}
	return cmd
}

// rebuild replaces a completed form with a fresh one holding the same values.
func (l *launchModel) rebuild() tea.Cmd {
	l.form = l.buildForm()
	return l.Init()
}

// options turns the form values into engine options. The target is always the
// normalized value, never the raw input.
func (l *launchModel) options() (engine.Options, error) {
	t, err := engine.NormalizeTarget(l.target)
	if err != nil {
		return engine.Options{}, errors.New("not a valid domain")
	}
	o := engine.Options{Target: t}
	on := presetByID(l.preset).on
	if l.preset == "custom" {
		on = l.custom
	}
	applyToggles(&o, on)
	for _, f := range []struct {
		s   string
		dst *int
	}{{l.timeout, &o.Timeout}, {l.maxParam, &o.MaxParamURLs}} {
		if err := posInt(f.s); err != nil {
			return engine.Options{}, err
		}
		*f.dst, _ = strconv.Atoi(strings.TrimSpace(f.s)) // "" → 0 = engine default
	}
	return o, nil
}

// startRun checks the cap, creates the run dir, spawns the engine and waits
// for run_start. It runs as a tea.Cmd, off the Update goroutine.
func startRun(cfg Config, o engine.Options) tea.Cmd {
	return func() tea.Msg {
		runs, err := runstore.Discover(cfg.OutputsRoot)
		if err != nil {
			return launchResultMsg{err: err}
		}
		if runstore.ActiveCount(runs) >= maxActive {
			return launchResultMsg{capped: true}
		}
		dir, err := engine.NewRunDir(cfg.OutputsRoot, o.Target, time.Now())
		if err != nil {
			return launchResultMsg{err: err}
		}
		pid, err := engine.Spawn(cfg.EngineBin, engine.Argv(o, dir), dir)
		if err != nil {
			_ = os.RemoveAll(dir) // the leaf we just made; no phantom run
			return launchResultMsg{err: err}
		}
		// Spawn uses setsid, so the engine leads its own group (pgid == pid).
		info := runstore.RunInfo{Dir: dir, PID: pid, PGID: pid}
		started, stErr := runstore.PIDStart(pid)
		info.PIDStart = started
		if err := engine.WaitStarted(dir, launchWait); err != nil {
			if errors.Is(err, engine.ErrNoStart) {
				err = stopUnstarted(info, stErr == nil)
			}
			return launchResultMsg{err: err} // dir kept: engine.log explains why
		}
		return AttachMsg{Dir: dir}
	}
}

// stopUnstarted hard-kills an engine that never emitted run_start (guarded
// like any hard kill) and describes the outcome with the engine.log tail.
// known is false when the engine had already exited before its start time
// could be read; there is then nothing safe to signal.
func stopUnstarted(info runstore.RunInfo, known bool) error {
	outcome := "stopped"
	if known {
		if err := engine.HardKill(info, info.Dir); err != nil {
			outcome = "stop failed: " + err.Error()
		}
	}
	return fmt.Errorf("engine did not start within %s — %s\nengine.log tail:\n%s",
		launchWait, outcome, engine.LogTail(info.Dir, 20))
}

func (l *launchModel) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		l.width, l.height = msg.Width, msg.Height
		if l.state != launchEditing {
			return nil
		}
		_, cmd := l.form.Update(l.formSize()) // the form gets its pane, not the terminal
		return cmd
	case launchSubmitMsg:
		if l.state != launchEditing {
			return nil
		}
		o, err := l.options()
		if err != nil {
			l.inlineErr = err.Error()
			return l.rebuild()
		}
		l.state, l.inlineErr = launchStarting, ""
		return startRun(l.cfg, o)
	case launchResultMsg:
		if msg.capped {
			l.state, l.inlineErr = launchEditing, capError
			return l.rebuild()
		}
		l.state = launchFailed
		l.failure = nil
		for _, line := range strings.Split(msg.err.Error(), "\n") {
			l.failure = append(l.failure, expandTabs(sanitize(line))) // engine.log is tool output
		}
		return nil
	case tea.KeyPressMsg:
		switch msg.String() {
		case "ctrl+c":
			return tea.Quit
		case "esc":
			if l.state == launchStarting {
				return nil // the spawn is in flight; its result decides the screen
			}
			return func() tea.Msg { return ShowRunsMsg{} }
		}
		if l.state != launchEditing {
			return nil
		}
	}
	if l.state != launchEditing {
		return nil
	}
	_, cmd := l.form.Update(msg)
	return cmd
}

// Launch layout: the form pane, with the banner beside it when it fits.
const (
	launchPaneW = 52 // form pane, border and padding included
	launchGap   = 3
)

func (l *launchModel) showBanner() bool {
	return l.state != launchFailed && l.width >= launchPaneW+launchGap+bannerWidth() &&
		l.height >= bannerHeight()+2
}

func (l *launchModel) paneWidth() int {
	if l.showBanner() || l.width <= 0 {
		return launchPaneW
	}
	return min(max(l.width, 40), 100)
}

// formSize is the WindowSizeMsg the huh form sees: the pane's inner area.
func (l *launchModel) formSize() tea.WindowSizeMsg {
	return tea.WindowSizeMsg{Width: l.paneWidth() - 4, Height: max(l.height-4, 10)}
}

func (l *launchModel) View() string {
	var b strings.Builder
	var help string
	switch l.state {
	case launchEditing:
		b.WriteString(l.form.View())
		if l.inlineErr != "" {
			b.WriteString("\n" + badStyle.Render("✗ "+l.inlineErr))
		}
		help = helpBar("enter next", "shift+tab back", "space/x toggle", "esc back")
	case launchStarting:
		b.WriteString(runStyle.Render("●") + " " + dimStyle.Render("starting engine…"))
		help = dimStyle.Render("waiting for run_start")
	case launchFailed:
		b.WriteString(badStyle.Bold(true).Render("✗ launch failed") + "\n\n")
		b.WriteString(strings.Join(l.failure, "\n"))
		help = helpBar("esc back")
	}
	box := paneBox(true).Width(l.paneWidth()).Render(strings.TrimRight(b.String(), "\n"))
	if l.showBanner() {
		box = lipgloss.JoinHorizontal(lipgloss.Top, box, strings.Repeat(" ", launchGap), bannerView())
	}
	return headerBar("New run", "") + "\n" + box + "\n" + help
}

// formTheme is huh's Charm theme recoloured to the app palette: red accent
// for the focused field, muted descriptions, green selections.
func formTheme(isDark bool) *huh.Styles {
	t := huh.ThemeCharm(isDark)
	f := &t.Focused
	f.Base = f.Base.BorderForeground(colRed)
	f.Title = f.Title.Foreground(colRed).Bold(true)
	f.Description = f.Description.Foreground(colMuted)
	f.ErrorIndicator = f.ErrorIndicator.Foreground(colRed)
	f.ErrorMessage = f.ErrorMessage.Foreground(colRed)
	f.SelectSelector = f.SelectSelector.Foreground(colRed)
	f.MultiSelectSelector = f.MultiSelectSelector.Foreground(colRed)
	f.SelectedOption = f.SelectedOption.Foreground(colGreen)
	f.SelectedPrefix = f.SelectedPrefix.Foreground(colGreen)
	f.UnselectedOption = f.UnselectedOption.Foreground(colText)
	f.UnselectedPrefix = f.UnselectedPrefix.Foreground(colFaint)
	f.TextInput.Cursor = f.TextInput.Cursor.Foreground(colRed)
	f.TextInput.Prompt = f.TextInput.Prompt.Foreground(colRed)
	f.TextInput.Placeholder = f.TextInput.Placeholder.Foreground(colFaint)
	f.FocusedButton = f.FocusedButton.Background(colRed).Foreground(colBase)
	f.Next = f.FocusedButton
	t.Blurred = *f
	t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Title = t.Blurred.Title.Foreground(colMuted).Bold(false)
	t.Blurred.MultiSelectSelector = t.Blurred.MultiSelectSelector.SetString("  ")
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()
	t.Help.ShortKey = t.Help.ShortKey.Foreground(colText)
	t.Help.ShortDesc = t.Help.ShortDesc.Foreground(colMuted)
	t.Help.ShortSeparator = t.Help.ShortSeparator.Foreground(colFaint)
	return t
}

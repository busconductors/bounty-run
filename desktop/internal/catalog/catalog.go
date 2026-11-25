// Package catalog describes what the engine can run, for the Launch screen:
// its stages and tools (from `bounty-run introspect`), the shared presets and
// a preview of the exact command a launch request spawns.
//
// Nothing here hard-codes the stage list: stages come from the engine at run
// time. What is fixed is how a stage selection maps onto engine.Options,
// because those are named Go fields (the opt-in flags and modifiers below).
package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"bountyrun/desktop/internal/runs"
	"github.com/busconductors/bounty-run/core/engine"
	"github.com/busconductors/bounty-run/core/textsafe"
)

// RunDirPlaceholder stands in for the run directory's timestamped leaf in a
// preview: StartRun makes the real one (root/<target>/<stamp>) at launch, and
// that substitution is the only way a preview differs from the spawned argv.
const RunDirPlaceholder = "YYYYMMDD-HHMMSS"

// Required warnings. The texts are part of the Launch contract.
const (
	WarnProxy      = "Proxy set: nmap and DNS stay direct, tools that cannot use the proxy are skipped, no origin IP is scanned, and child tools can expose proxy credentials in the local process list."
	WarnScopeAllow = "--scope-allow set: it replaces the default target-plus-subdomains scope."
	WarnUnredacted = "--evidence-unredacted set: stored evidence may contain secrets."
	WarnMissing    = "Selected stage has a missing tool"
	// WarnToolsUnavailable prefixes the warning shown while the tool check is
	// still running or has failed: missing-tool warnings cannot be given then.
	WarnToolsUnavailable = "Tool status unavailable"
)

const (
	reportSchema    = 1
	maxReportBytes  = 4 << 20
	maxStderrBytes  = 8 << 10
	introspectLimit = 30 * time.Second
	doctorLimit     = 120 * time.Second // ~20 tools, each probe capped at 3 s
	maxTitleBytes   = 120

	// doctorPreviewWait is the longest Preview waits for a running tool check
	// before answering without it.
	doctorPreviewWait = 1500 * time.Millisecond
	// doctorRetryAfter is how long a failed tool check is reported as is
	// before the next Preview or Doctor call tries again.
	doctorRetryAfter = 30 * time.Second
)

// Tiers in ceiling order (runner/stage_registry.py Tier).
var tiers = []string{"passive", "active", "intrusive"}

var (
	stageIDRE  = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

// optInFlags maps an engine opt-in stage to the Options field that enables it.
var optInFlags = map[string]func(*engine.Options) *bool{
	"nmap":  func(o *engine.Options) *bool { return &o.Nmap },
	"tls":   func(o *engine.Options) *bool { return &o.TLS },
	"nikto": func(o *engine.Options) *bool { return &o.Nikto },
	"metis": func(o *engine.Options) *bool { return &o.Metis },
	"headi": func(o *engine.Options) *bool { return &o.Headi },
}

// Modifier is a toggle with no stage of its own that refines one (Parent).
type Modifier struct {
	ID     string `json:"id"`
	Parent string `json:"parent"`
	Title  string `json:"title"`
	set    func(*engine.Options)
}

var modifiers = []Modifier{
	{ID: "amass", Parent: "subs", Title: "AMASS PASSIVE ENUM", set: func(o *engine.Options) { o.Amass = true }},
	{ID: "findomain", Parent: "subs", Title: "FINDOMAIN PASSIVE ENUM", set: func(o *engine.Options) { o.Findomain = true }},
	{ID: "nmap-full", Parent: "nmap", Title: "ALL 65535 PORTS", set: func(o *engine.Options) { o.NmapFull = true }},
}

// Stage is one engine stage, as reported by `introspect stages`.
type Stage struct {
	ID     string   `json:"id"`
	Num    int      `json:"num"`
	Title  string   `json:"title"`
	Tier   string   `json:"tier"`
	Caps   []string `json:"caps"`
	OptIn  bool     `json:"opt_in"`
	Parent string   `json:"parent,omitempty"`
}

// Preset is a named selection of stages and modifiers.
type Preset struct {
	ID     string   `json:"id"`
	Stages []string `json:"stages"`
}

// Tool is one row of `introspect doctor`.
type Tool struct {
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	Version     string   `json:"version"`
	RequiredBy  []string `json:"required_by"`
	Optional    bool     `json:"optional"`
	InstallHint string   `json:"install_hint"`
	Status      string   `json:"status"` // ok | missing | unknown_version
}

// Doctor is the engine's tool report plus, per stage or modifier id, the
// missing tools that stop it from doing its job (see missingByStage).
type Doctor struct {
	Tools          []Tool              `json:"tools"`
	MissingByStage map[string][]string `json:"missing_by_stage"`
}

// Version is `introspect version`.
type Version struct {
	Engine       string `json:"engine_version"`
	EventsSchema int    `json:"events_schema"`
}

// Request is what the Launch form submits. Stages lists the enabled stage and
// modifier ids; it replaces every stage field of Options (the opt-in flags,
// the modifiers and Skip), so those are computed here and never trusted from
// the client.
type Request struct {
	Options engine.Options `json:"options"`
	Stages  []string       `json:"stages"`
}

// Scope is the effective engagement scope a launch would use.
type Scope struct {
	Default bool     `json:"default"` // target plus its subdomains
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
	File    string   `json:"file,omitempty"`
}

// PreviewResult is what Launch shows before starting. Argv is the full
// command (engine binary first); EnvNames are the names, never the values, of
// the extra environment the engine gets.
type PreviewResult struct {
	Target   string   `json:"target"`
	Argv     []string `json:"argv"`
	EnvNames []string `json:"env_names"`
	Warnings []string `json:"warnings"`
	Scope    Scope    `json:"scope"`
	RunDir   string   `json:"run_dir"`
}

// Config configures a Catalog. Root is the outputs root (runs.OutputsRoot
// when empty); EngineBin is resolved with runs.EngineBin at each call when
// empty; Exec runs the engine and returns its stdout (tests inject one).
type Config struct {
	Root      string
	EngineBin string
	Exec      func(bin string, args ...string) ([]byte, error)
}

// Catalog caches successful introspection results. Safe for concurrent use.
type Catalog struct {
	root string
	bin  string
	exec func(bin string, args ...string) ([]byte, error)

	stagesMu sync.Mutex
	stages   []Stage
	// The tool check runs at most once at a time (single flight) and never
	// under a lock a caller waits on, so a hanging `introspect doctor` cannot
	// stall Preview.
	doctorMu       sync.Mutex
	doctor         *Doctor       // last successful report
	doctorErr      error         // error of the last run, nil if it succeeded
	doctorErrAt    time.Time     // when doctorErr was recorded
	doctorInflight chan struct{} // closed when the running check ends
}

// New returns a Catalog.
func New(cfg Config) *Catalog {
	c := &Catalog{root: cfg.Root, bin: cfg.EngineBin, exec: cfg.Exec}
	if c.exec == nil {
		c.exec = runEngine
	}
	return c
}

func (c *Catalog) engineBin() (string, error) {
	if c.bin != "" {
		return c.bin, nil
	}
	return runs.EngineBin()
}

func (c *Catalog) outputsRoot() (string, error) {
	if c.root != "" {
		return c.root, nil
	}
	return runs.OutputsRoot()
}

func (c *Catalog) introspect(what string, into any) error {
	bin, err := c.engineBin()
	if err != nil {
		return err
	}
	out, err := c.exec(bin, "introspect", what)
	if err != nil {
		return fmt.Errorf("engine introspect %s: %w", what, err)
	}
	if err := json.Unmarshal(out, into); err != nil {
		return fmt.Errorf("engine introspect %s: bad JSON: %w", what, err)
	}
	return nil
}

// Stages returns the engine's stages in pipeline order.
func (c *Catalog) Stages() ([]Stage, error) {
	c.stagesMu.Lock()
	defer c.stagesMu.Unlock()
	if c.stages != nil {
		return slices.Clone(c.stages), nil
	}
	var rep struct {
		Schema int `json:"schema"`
		Stages []struct {
			Stage
			Parent *string `json:"parent"`
		} `json:"stages"`
	}
	if err := c.introspect("stages", &rep); err != nil {
		return nil, err
	}
	if rep.Schema != reportSchema {
		return nil, fmt.Errorf("engine stage report schema %d, want %d", rep.Schema, reportSchema)
	}
	if len(rep.Stages) == 0 {
		return nil, errors.New("engine reported no stages")
	}
	seen := map[string]bool{}
	out := make([]Stage, 0, len(rep.Stages))
	for _, s := range rep.Stages {
		st := s.Stage
		if s.Parent != nil {
			st.Parent = *s.Parent
		}
		if !stageIDRE.MatchString(st.ID) || seen[st.ID] {
			return nil, fmt.Errorf("engine reported a bad or duplicate stage id %q", textsafe.OneLine(st.ID))
		}
		if !slices.Contains(tiers, st.Tier) {
			return nil, fmt.Errorf("stage %s: unknown tier %q", st.ID, textsafe.OneLine(st.Tier))
		}
		if st.Parent != "" && !seen[st.Parent] {
			return nil, fmt.Errorf("stage %s: parent %q is not an earlier stage", st.ID, textsafe.OneLine(st.Parent))
		}
		st.Title = clip(textsafe.OneLine(st.Title), maxTitleBytes)
		caps := st.Caps[:0:0]
		for _, cp := range st.Caps {
			if stageIDRE.MatchString(cp) {
				caps = append(caps, cp)
			}
		}
		st.Caps = caps
		seen[st.ID] = true
		out = append(out, st)
	}
	c.stages = out
	return slices.Clone(out), nil
}

// Modifiers returns the modifiers whose parent stage the engine reports.
func (c *Catalog) Modifiers() ([]Modifier, error) {
	stages, err := c.Stages()
	if err != nil {
		return nil, err
	}
	var out []Modifier
	for _, m := range modifiers {
		if slices.ContainsFunc(stages, func(s Stage) bool { return s.ID == m.Parent }) {
			out = append(out, m)
		}
	}
	return out, nil
}

// Presets returns Quick, Standard and Deep (engine.Presets) as flat lists of
// enabled stage and modifier ids.
func (c *Catalog) Presets() []Preset {
	var out []Preset
	for _, p := range engine.Presets() {
		out = append(out, Preset{ID: p.ID, Stages: append(slices.Clone(p.Stages), p.Flags...)})
	}
	return out
}

// Version returns the engine's version report.
func (c *Catalog) Version() (Version, error) {
	var rep struct {
		Schema int `json:"schema"`
		Version
	}
	if err := c.introspect("version", &rep); err != nil {
		return Version{}, err
	}
	if rep.Schema != reportSchema {
		return Version{}, fmt.Errorf("engine version report schema %d, want %d", rep.Schema, reportSchema)
	}
	rep.Engine = clip(textsafe.OneLine(rep.Engine), maxTitleBytes)
	return rep.Version, nil
}

// Doctor returns the engine's tool report, cached after the first success.
func (c *Catalog) Doctor() (Doctor, error) { return c.loadDoctor(false) }

// RecheckDoctor re-runs the engine's tool report.
func (c *Catalog) RecheckDoctor() (Doctor, error) { return c.loadDoctor(true) }

// errToolsPending means the tool check is still running.
var errToolsPending = errors.New("still checking tools")

// loadDoctor returns the cached report, or the failure of a check that ended
// less than doctorRetryAfter ago; otherwise (or when fresh) it joins or starts
// a check and waits for it.
func (c *Catalog) loadDoctor(fresh bool) (Doctor, error) {
	c.doctorMu.Lock()
	if !fresh {
		if d, err, ok := c.doctorCachedLocked(); ok {
			c.doctorMu.Unlock()
			return d, err
		}
	}
	// A recheck must report a run that began after the request, so it waits
	// out a check already in flight (its probes may predate the request) and
	// then joins or starts the next one.
	for fresh && c.doctorInflight != nil {
		running := c.doctorInflight
		c.doctorMu.Unlock()
		<-running
		c.doctorMu.Lock()
	}
	done := c.startDoctorLocked()
	c.doctorMu.Unlock()
	<-done
	return c.doctorResult()
}

// doctorWithin is loadDoctor(false) for Preview: it waits at most wait for a
// running check and then reports errToolsPending.
func (c *Catalog) doctorWithin(wait time.Duration) (Doctor, error) {
	c.doctorMu.Lock()
	if d, err, ok := c.doctorCachedLocked(); ok {
		c.doctorMu.Unlock()
		return d, err
	}
	done := c.startDoctorLocked()
	c.doctorMu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-done:
		return c.doctorResult()
	case <-timer.C:
		return Doctor{}, errToolsPending
	}
}

// doctorCachedLocked reports a usable cached outcome: the last check's
// success, or its failure while that is recent. Requires doctorMu.
func (c *Catalog) doctorCachedLocked() (Doctor, error, bool) {
	switch {
	case c.doctorInflight != nil:
		return Doctor{}, nil, false
	case c.doctorErr != nil && time.Since(c.doctorErrAt) < doctorRetryAfter:
		return Doctor{}, c.doctorErr, true
	case c.doctorErr == nil && c.doctor != nil:
		return *c.doctor, nil, true
	}
	return Doctor{}, nil, false
}

// startDoctorLocked joins the running check or starts one. Requires doctorMu.
func (c *Catalog) startDoctorLocked() <-chan struct{} {
	if c.doctorInflight != nil {
		return c.doctorInflight
	}
	done := make(chan struct{})
	c.doctorInflight = done
	go func() {
		d, err := c.runDoctor()
		c.doctorMu.Lock()
		if err == nil {
			c.doctor = &d
		}
		c.doctorErr, c.doctorErrAt = err, time.Now()
		c.doctorInflight = nil
		close(done)
		c.doctorMu.Unlock()
	}()
	return done
}

func (c *Catalog) doctorResult() (Doctor, error) {
	c.doctorMu.Lock()
	defer c.doctorMu.Unlock()
	if c.doctorErr != nil || c.doctor == nil {
		return Doctor{}, c.doctorErr
	}
	return *c.doctor, nil
}

func (c *Catalog) runDoctor() (Doctor, error) {
	var rep struct {
		Schema int `json:"schema"`
		Tools  []struct {
			Tool
			Path    *string `json:"path"`
			Version *string `json:"version"`
		} `json:"tools"`
	}
	if err := c.introspect("doctor", &rep); err != nil {
		return Doctor{}, err
	}
	if rep.Schema != reportSchema {
		return Doctor{}, fmt.Errorf("engine doctor report schema %d, want %d", rep.Schema, reportSchema)
	}
	stages, _ := c.Stages() // without stages, optional tools never count as missing
	d := Doctor{Tools: make([]Tool, 0, len(rep.Tools))}
	for _, r := range rep.Tools {
		t := r.Tool
		if r.Path != nil {
			t.Path = *r.Path
		}
		if r.Version != nil {
			t.Version = *r.Version
		}
		t.Name = clip(textsafe.OneLine(t.Name), maxTitleBytes)
		t.Path = textsafe.OneLine(t.Path)
		t.Version = clip(textsafe.OneLine(t.Version), maxTitleBytes)
		t.InstallHint = textsafe.OneLine(t.InstallHint)
		t.Status = textsafe.OneLine(t.Status)
		d.Tools = append(d.Tools, t)
	}
	d.MissingByStage = missingByStage(d.Tools, stages)
	return d, nil
}

// missingByStage lists, per stage or modifier id, the missing tools it needs.
// Only status "missing" counts (unknown_version means present without a
// version string). A required tool counts for every stage that needs it. An
// optional tool counts only where it is the point of the toggle: for an
// opt-in stage that needs it, or for the modifier of the same name (amass);
// elsewhere the engine degrades without it (dnsx for subs).
func missingByStage(tools []Tool, stages []Stage) map[string][]string {
	optIn := map[string]bool{}
	for _, s := range stages {
		optIn[s.ID] = s.OptIn
	}
	isModifier := func(id string) bool {
		return slices.ContainsFunc(modifiers, func(m Modifier) bool { return m.ID == id })
	}
	out := map[string][]string{}
	add := func(id, tool string) {
		if !slices.Contains(out[id], tool) {
			out[id] = append(out[id], tool)
		}
	}
	for _, t := range tools {
		if t.Status != "missing" {
			continue
		}
		if t.Optional && isModifier(t.Name) {
			add(t.Name, t.Name)
			continue
		}
		for _, id := range t.RequiredBy {
			if !t.Optional || optIn[id] {
				add(id, t.Name)
			}
		}
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out
}

// selection is a resolved request: the options plus which enabled ids will
// actually run under the intensity ceiling.
type selection struct {
	opts   engine.Options
	active []string // runnable stage and modifier ids, pipeline order
}

// Resolve turns a request into the engine.Options StartRun takes, validated
// and normalized by runs.Prepare (what StartRun itself applies).
func (c *Catalog) Resolve(r Request) (engine.Options, error) {
	sel, err := c.resolve(r)
	return sel.opts, err
}

func (c *Catalog) resolve(r Request) (selection, error) {
	o := r.Options
	ceiling := len(tiers) - 1 // the engine's default ceiling is intrusive
	if o.Intensity != "" {
		ceiling = slices.Index(tiers, o.Intensity)
		if ceiling < 0 {
			return selection{}, fmt.Errorf("unknown intensity %q", textsafe.OneLine(o.Intensity))
		}
	}
	stages, err := c.Stages()
	if err != nil {
		return selection{}, err
	}
	mods, _ := c.Modifiers()
	enabled := map[string]bool{}
	for _, id := range r.Stages {
		known := slices.ContainsFunc(stages, func(s Stage) bool { return s.ID == id }) ||
			slices.ContainsFunc(mods, func(m Modifier) bool { return m.ID == id })
		if !known {
			return selection{}, fmt.Errorf("unknown stage %q", textsafe.OneLine(id))
		}
		enabled[id] = true
	}
	if len(enabled) == 0 {
		return selection{}, errors.New("select at least one stage")
	}

	// Every stage field comes from the selection, never from the client.
	o.Amass, o.Findomain, o.NmapFull = false, false, false
	o.Nmap, o.TLS, o.Nikto, o.Metis, o.Headi = false, false, false, false, false
	o.Skip = nil
	var active []string
	running := map[string]bool{}
	for _, s := range stages {
		gated := slices.Index(tiers, s.Tier) > ceiling // the engine gates it itself
		on := enabled[s.ID] && (s.Parent == "" || running[s.Parent])
		switch {
		case s.OptIn:
			flag, ok := optInFlags[s.ID]
			if on && !ok {
				return selection{}, fmt.Errorf("opt-in stage %q is not supported by this app", s.ID)
			}
			if on && !gated {
				*flag(&o) = true
			}
		case !on && !gated:
			o.Skip = append(o.Skip, s.ID)
		}
		if on && !gated {
			running[s.ID] = true
			active = append(active, s.ID)
		}
	}
	for _, m := range mods {
		if enabled[m.ID] && running[m.Parent] {
			m.set(&o)
			active = append(active, m.ID)
		}
	}

	if o.Headers, err = cleanHeaders(o.Headers); err != nil {
		return selection{}, err
	}
	if o.ScopeAllow, err = cleanList("scope allow rule", o.ScopeAllow); err != nil {
		return selection{}, err
	}
	if o.ScopeDeny, err = cleanList("scope deny rule", o.ScopeDeny); err != nil {
		return selection{}, err
	}
	for name, v := range map[string]*string{
		"scope file": &o.ScopeFile, "user agent": &o.UserAgent, "resolvers": &o.Resolvers,
		"wordlist": &o.Wordlist, "nuclei severity": &o.NucleiSeverity,
		"client": &o.Client, "engagement": &o.Engagement,
		"prepared by": &o.PreparedBy, "team": &o.Team,
	} {
		*v = strings.TrimSpace(*v)
		if hasControl(*v) {
			return selection{}, fmt.Errorf("%s must be one line without control characters", name)
		}
	}
	if o, err = runs.Prepare(o); err != nil {
		return selection{}, err
	}
	return selection{opts: o, active: active}, nil
}

// Preview returns the exact command a launch of r spawns, the names of its
// extra environment, the effective scope and every applicable warning.
func (c *Catalog) Preview(r Request) (PreviewResult, error) {
	sel, err := c.resolve(r)
	if err != nil {
		return PreviewResult{}, err
	}
	o := sel.opts
	bin, err := c.engineBin()
	if err != nil {
		return PreviewResult{}, err
	}
	root, err := c.outputsRoot()
	if err != nil {
		return PreviewResult{}, err
	}
	dir := filepath.Join(root, o.Target, RunDirPlaceholder)
	p := PreviewResult{
		Target:   o.Target,
		Argv:     append([]string{bin}, engine.PreviewArgv(o, dir)...),
		RunDir:   dir,
		Warnings: []string{},
		Scope:    Scope{Allow: o.ScopeAllow, Deny: o.ScopeDeny, File: o.ScopeFile},
	}
	for _, kv := range runs.SpawnEnv(o, root) {
		name, _, _ := strings.Cut(kv, "=")
		p.EnvNames = append(p.EnvNames, name)
	}
	if len(o.ScopeAllow) == 0 && o.ScopeFile == "" {
		p.Scope.Default = true
		p.Scope.Allow = []string{o.Target, "*." + o.Target}
	}
	if p.Scope.Allow == nil { // a scope file alone: no inline rules
		p.Scope.Allow = []string{}
	}
	if p.Scope.Deny == nil {
		p.Scope.Deny = []string{}
	}
	if o.Proxy != "" {
		p.Warnings = append(p.Warnings, WarnProxy)
	}
	if len(o.ScopeAllow) > 0 {
		p.Warnings = append(p.Warnings, WarnScopeAllow)
	}
	if o.EvidenceUnredacted {
		p.Warnings = append(p.Warnings, WarnUnredacted)
	}
	// Never block a preview on the tool check: answer without missing-tool
	// warnings (and say so) while it is running or has failed.
	d, err := c.doctorWithin(doctorPreviewWait)
	if err != nil {
		p.Warnings = append(p.Warnings, WarnToolsUnavailable+": "+textsafe.OneLine(err.Error())+".")
	}
	for _, id := range sel.active {
		if tools := d.MissingByStage[id]; len(tools) > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("%s: %s needs %s.", WarnMissing, id, strings.Join(tools, ", ")))
		}
	}
	return p, nil
}

// cleanHeaders trims headers, drops blank ones and rejects any that is not a
// single "Name: value" line.
func cleanHeaders(hs []string) ([]string, error) {
	var out []string
	for _, h := range hs {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		name, _, ok := strings.Cut(h, ":")
		if !ok || !headerName.MatchString(strings.TrimSpace(name)) || name != strings.TrimSpace(name) {
			return nil, errors.New(`each header must be "Name: value"`)
		}
		if hasControl(h) {
			return nil, errors.New("headers must be one line without control characters")
		}
		out = append(out, h)
	}
	return out, nil
}

// cleanList trims xs and drops blank and repeated entries, keeping the first
// occurrence's order. Preview and StartRun both use the result, so the argv
// and the shown scope stay identical.
func cleanList(what string, xs []string) ([]string, error) {
	var out []string
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" || slices.Contains(out, x) {
			continue
		}
		if hasControl(x) {
			return nil, fmt.Errorf("%s must be one line without control characters", what)
		}
		out = append(out, x)
	}
	return out, nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) })
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// runEngine runs `bin args...` with no stdin, the secret variables removed
// from its environment and a deadline, and returns its stdout.
func runEngine(bin string, args ...string) ([]byte, error) {
	limit := introspectLimit
	if slices.Contains(args, "doctor") {
		limit = doctorLimit
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, engine.ProxyEnvVar+"=") && !strings.HasPrefix(e, engine.HeadersEnvVar+"=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	stdout := &capped{max: maxReportBytes}
	stderr := &capped{max: maxStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if stdout.over {
		return nil, fmt.Errorf("output exceeds %d bytes", maxReportBytes)
	}
	if err != nil {
		msg := strings.TrimSpace(textsafe.Sanitize(stderr.String()))
		if msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

// capped keeps at most max bytes and notes any overflow.
type capped struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room < len(p) {
		c.over = true
		if room > 0 {
			c.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

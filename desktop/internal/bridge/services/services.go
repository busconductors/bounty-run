// Package services binds the run backend and the engine catalog to the
// frontend as Wails services. The frontend calls them by fully qualified name
// (see frontend/src/lib/bridge/api.js), e.g.
// "bountyrun/desktop/internal/bridge/services.Launch.Preview".
//
// Errors reach the frontend as a RuntimeError whose cause is an ErrorInfo.
package services

import (
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/wailsapp/wails/v3/pkg/application"

	"bountyrun/core/runstore"
	"bountyrun/desktop/internal/catalog"
	"bountyrun/desktop/internal/doctor"
	"bountyrun/desktop/internal/findings"
	"bountyrun/desktop/internal/reports"
	"bountyrun/desktop/internal/runs"
)

// Launch serves the Launch screen.
type Launch struct {
	cat  *catalog.Catalog
	runs *runs.Service
}

// Stages returns the engine's stages in pipeline order.
func (l *Launch) Stages() ([]catalog.Stage, error) { return l.cat.Stages() }

// Modifiers returns the stage modifiers (amass, findomain, nmap-full).
func (l *Launch) Modifiers() ([]catalog.Modifier, error) { return l.cat.Modifiers() }

// Presets returns Quick, Standard and Deep.
func (l *Launch) Presets() []catalog.Preset { return l.cat.Presets() }

// Doctor returns the engine's tool report (cached).
func (l *Launch) Doctor() (catalog.Doctor, error) { return l.cat.Doctor() }

// Version returns the engine version.
func (l *Launch) Version() (catalog.Version, error) { return l.cat.Version() }

// Preview returns the exact command Start would spawn for r.
func (l *Launch) Preview(r catalog.Request) (catalog.PreviewResult, error) { return l.cat.Preview(r) }

// Start launches r. It resolves r exactly as Preview does.
func (l *Launch) Start(r catalog.Request) (runs.RunRef, error) {
	o, err := l.cat.Resolve(r)
	if err != nil {
		return runs.RunRef{}, err
	}
	return l.runs.StartRun(o)
}

// Doctor serves the Doctor screen.
type Doctor struct {
	svc *doctor.Service
}

// Report returns the toolchain report (cached).
func (d *Doctor) Report() (doctor.Report, error) { return d.svc.Report() }

// Recheck re-runs the toolchain check.
func (d *Doctor) Recheck() (doctor.Report, error) { return d.svc.Recheck() }

// Findings serves the Findings view.
type Findings struct {
	svc *findings.Service
}

// GetFindings returns the findings of the run in dir (a run under the outputs root).
func (f *Findings) GetFindings(dir string) (findings.FindingsResult, error) {
	return f.svc.GetFindings(dir)
}

// ReportInfo says which report files a run has. HTML is summary.html (shown
// in the sandboxed viewer); Markdown lists the files that can be opened
// externally.
type ReportInfo struct {
	HTML     bool     `json:"html"`
	Markdown []string `json:"markdown"`
	PDF      bool     `json:"pdf"`
}

// Reports serves the report viewer's backend.
type Reports struct {
	root   string
	runDir func(dir string) (string, error)
	open   func(path string) error
}

// Available returns which report files the run in dir has.
func (r *Reports) Available(dir string) (ReportInfo, error) {
	dir, err := r.runDir(dir)
	if err != nil {
		return ReportInfo{}, err
	}
	info := ReportInfo{Markdown: []string{}}
	_, herr := reports.SafeFile(r.root, dir, reports.HTMLReport, []string{reports.HTMLReport})
	info.HTML = herr == nil
	_, perr := reports.SafeFile(r.root, dir, reports.PDFReport, []string{reports.PDFReport})
	info.PDF = perr == nil
	for _, name := range reports.MarkdownReports {
		if _, err := reports.SafeFile(r.root, dir, name, reports.MarkdownReports); err == nil {
			info.Markdown = append(info.Markdown, name)
		}
	}
	return info, nil
}

// OpenExternal opens FINDINGS.md, SUMMARY.md or report.pdf of the run in dir with the OS
// default handler. The path is validated like the viewer's; the name is
// matched against an allowlist and never reaches a shell.
func (r *Reports) OpenExternal(dir, name string) error {
	dir, err := r.runDir(dir)
	if err != nil {
		return err
	}
	path, err := reports.SafeFile(r.root, dir, name, append(append([]string{}, reports.MarkdownReports...), reports.PDFReport))
	if err != nil {
		return err
	}
	return r.open(path)
}

// renderReportPDF renders the HTML file at htmlPath to a PDF at pdfPath using
// the platform's WebKit print path (webkitRenderPDF). theme is "light" or
// "dark". It is a package variable so tests can swap in a stub and never drive
// real WebKit.
var renderReportPDF = webkitRenderPDF

// ExportPDF renders the run's summary.html to report.pdf in the same run dir
// and returns the saved path. theme is "dark" to keep the report's dark
// treatment in print (the renderer sets html[data-pdf-theme="dark"] first);
// "", "light" or any other value render the light print theme.
func (r *Reports) ExportPDF(dir, theme string) (string, error) {
	dir, err := r.runDir(dir)
	if err != nil {
		return "", err
	}
	html, err := reports.SafeFile(r.root, dir, reports.HTMLReport, []string{reports.HTMLReport})
	if err != nil {
		return "", err
	}
	if theme != "dark" {
		theme = "light"
	}
	pdf := filepath.Join(dir, reports.PDFReport)
	if err := renderReportPDF(html, pdf, theme); err != nil {
		return "", err
	}
	return pdf, nil
}

// openWithOS launches the OS default handler for path without a shell.
func openWithOS(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", "--", path)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", filepath.Clean(path))
	default:
		cmd = exec.Command("xdg-open", path)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// Runs exposes run control and streaming.
type Runs struct {
	svc *runs.Service
}

// ListRuns returns every run, running ones first.
func (r *Runs) ListRuns() ([]runstore.Run, error) { return r.svc.ListRuns() }

// Attach starts streaming the run in dir.
func (r *Runs) Attach(dir string) (runs.Snapshot, error) { return r.svc.Attach(dir) }

// RunID returns the id in the run's channel names (run:<id>:batch and
// run:<id>:dead), so the frontend can subscribe before it attaches.
func (r *Runs) RunID(dir string) string { return runs.RunID(dir) }

// Detach stops streaming dir; the engine keeps running.
func (r *Runs) Detach(dir string) { r.svc.Detach(dir) }

// Skip asks the engine to skip stage.
func (r *Runs) Skip(dir, stage string) error { return r.svc.Skip(dir, stage) }

// Cancel asks the engine to cancel the run.
func (r *Runs) Cancel(dir string) error { return r.svc.Cancel(dir) }

// HardKill SIGKILLs the run's engine and tools.
func (r *Runs) HardKill(dir string) error { return r.svc.HardKill(dir) }

// EngineLogTail returns the sanitized last n lines of the run's engine.log.
func (r *Runs) EngineLogTail(dir string, n int) string { return r.svc.EngineLogTail(dir, n) }

// ServiceShutdown detaches every run when the app quits. Engines keep running.
func (r *Runs) ServiceShutdown() error {
	r.svc.Close()
	return nil
}

// ErrorInfo is the cause the frontend receives with a failed call. Kind is
// "launch" (the engine never started; Tail is its sanitized engine.log tail
// and Dir the kept run dir), "cap" (too many active runs) or "error".
type ErrorInfo struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Tail    string `json:"tail,omitempty"`
	Dir     string `json:"dir,omitempty"`
}

func errorInfo(err error) ErrorInfo {
	var le *runs.LaunchError
	switch {
	case errors.As(err, &le):
		msg := "engine exited before starting"
		if le.Outcome != "" {
			msg = "engine did not start in time — " + le.Outcome
		}
		return ErrorInfo{Kind: "launch", Message: msg, Tail: le.Tail, Dir: le.Dir}
	case errors.Is(err, runs.ErrCapReached):
		return ErrorInfo{Kind: "cap", Message: err.Error()}
	default:
		return ErrorInfo{Kind: "error", Message: err.Error()}
	}
}

func marshalError(err error) []byte {
	b, jerr := json.Marshal(errorInfo(err))
	if jerr != nil {
		return nil
	}
	return b
}

// Bind returns the services to register with the application.
func Bind(svc *runs.Service, cat *catalog.Catalog) []application.Service {
	opts := application.ServiceOptions{MarshalError: marshalError}
	return []application.Service{
		application.NewServiceWithOptions(&Launch{cat: cat, runs: svc}, opts),
		application.NewServiceWithOptions(&Runs{svc: svc}, opts),
		application.NewServiceWithOptions(&Findings{svc: findings.New(svc.RunDir)}, opts),
		application.NewServiceWithOptions(&Reports{root: svc.Root(), runDir: svc.RunDir, open: openWithOS}, opts),
		application.NewServiceWithOptions(&Doctor{svc: doctor.New(cat)}, opts),
	}
}

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

	"github.com/wailsapp/wails/v3/pkg/application"

	"bountyrun/core/runstore"
	"bountyrun/desktop/internal/catalog"
	"bountyrun/desktop/internal/doctor"
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
		application.NewServiceWithOptions(&Doctor{svc: doctor.New(cat)}, opts),
	}
}

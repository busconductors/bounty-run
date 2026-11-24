// Package shell owns the Wails application and its single frameless window.
// It is kept apart from package bridge so services can use bridge.Emitter
// without linking the native toolkit.
package shell

import (
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/wailsapp/wails/v3/pkg/application"

	"bountyrun/desktop/internal/bridge"
	"bountyrun/desktop/internal/reports"
)

const (
	appName       = "Bounty Runner"
	programName   = "bounty-runner"
	windowWidth   = 1280
	windowHeight  = 800
	minWindowW    = 1024
	minWindowH    = 640
	backgroundRed = 0x0f // --bg-1
	backgroundGrn = 0x0f
	backgroundBlu = 0x10
)

// Shell is a configured application that has not started yet.
type Shell struct {
	app *application.App
}

// New builds the application and its window around the given frontend assets.
// Requests under /reports/ are answered from the runs under runsRoot.
func New(assets fs.FS, runsRoot string) *Shell {
	app := application.New(appOptions(assets, runsRoot))
	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            appName,
		Width:            windowWidth,
		Height:           windowHeight,
		MinWidth:         minWindowW,
		MinHeight:        minWindowH,
		Frameless:        true,
		BackgroundColour: application.NewRGB(backgroundRed, backgroundGrn, backgroundBlu),
		URL:              "/",
	})
	return &Shell{app: app}
}

// appOptions configures the application. Wails logs every binding call's
// arguments at debug level, and launch requests carry the proxy and headers,
// so the system log never goes below info (and is discarded entirely in
// production builds).
func appOptions(assets fs.FS, runsRoot string) application.Options {
	handler := reports.Mount(reports.New(runsRoot), http.Handler(application.AssetFileServerFS(assets)))
	return application.Options{
		Name:     appName,
		Assets:   application.AssetOptions{Handler: handler},
		Linux:    application.LinuxOptions{ProgramName: programName},
		LogLevel: slog.LevelInfo,
	}
}

// Emitter returns the event channel services use to reach the frontend.
func (s *Shell) Emitter() bridge.Emitter {
	return emitter{events: s.app.Event}
}

// Register binds services to the frontend. Call it before Run.
func (s *Shell) Register(services ...application.Service) {
	for _, svc := range services {
		s.app.RegisterService(svc)
	}
}

// Run blocks until the last window closes.
func (s *Shell) Run() error {
	return s.app.Run()
}

type eventSink interface {
	Emit(name string, data ...any) bool
}

type emitter struct {
	events eventSink
}

func (e emitter) Emit(channel string, payload any) {
	e.events.Emit(channel, payload)
}

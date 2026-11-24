// Package shell owns the Wails application and its single frameless window.
// It is kept apart from package bridge so services can use bridge.Emitter
// without linking the native toolkit.
package shell

import (
	"io/fs"

	"github.com/wailsapp/wails/v3/pkg/application"

	"bountyrun/desktop/internal/bridge"
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
func New(assets fs.FS) *Shell {
	app := application.New(application.Options{
		Name:   appName,
		Assets: application.AssetOptions{Handler: application.AssetFileServerFS(assets)},
		Linux:  application.LinuxOptions{ProgramName: programName},
	})
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

// Emitter returns the event channel services use to reach the frontend.
func (s *Shell) Emitter() bridge.Emitter {
	return emitter{events: s.app.Event}
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

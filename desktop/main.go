// Command bounty-runner is the Bounty Runner desktop application.
//
// main is the composition root but does not import Wails itself: every Wails
// import lives under internal/bridge, which TestNoWailsImportOutsideBridge
// enforces with no exception for this file. The shell serves the embedded
// frontend in-process and opens no network listener.
package main

import (
	"log"

	"bountyrun/desktop/internal/bridge/services"
	"bountyrun/desktop/internal/bridge/shell"
	"bountyrun/desktop/internal/catalog"
	"bountyrun/desktop/internal/runs"
)

func main() {
	assets, err := frontendAssets()
	if err != nil {
		log.Fatal(err)
	}
	root, err := runs.OutputsRoot()
	if err != nil {
		log.Fatal(err)
	}
	app := shell.New(assets, root)
	svc, err := runs.New(runs.Config{Root: root, Emitter: app.Emitter()})
	if err != nil {
		log.Fatal(err)
	}
	// The services' shutdown hook detaches runs; engines keep running.
	app.Register(services.Bind(svc, catalog.New(catalog.Config{Root: svc.Root()}))...)
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

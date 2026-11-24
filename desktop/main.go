// Command bounty-runner is the Bounty Runner desktop application.
//
// main is the composition root but does not import Wails itself: every Wails
// import lives under internal/bridge, which TestNoWailsImportOutsideBridge
// enforces with no exception for this file. The shell serves the embedded
// frontend in-process and opens no network listener.
package main

import (
	"log"

	"bountyrun/desktop/internal/bridge/shell"
)

func main() {
	assets, err := frontendAssets()
	if err != nil {
		log.Fatal(err)
	}
	if err := shell.New(assets).Run(); err != nil {
		log.Fatal(err)
	}
}

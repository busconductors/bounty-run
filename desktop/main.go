// Command bounty-runner is the Bounty Runner desktop application.
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

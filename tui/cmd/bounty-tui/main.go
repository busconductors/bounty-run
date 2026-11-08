package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tea "charm.land/bubbletea/v2"

	"bountyrun/tui/internal/ui"
)

const version = "0.1.0-dev"

func main() {
	outputs := flag.String("outputs", "", "outputs root (default $BOUNTY_OUTPUTS or ~/tools/bounty-run/outputs)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("bounty-tui", version)
		return
	}
	root := *outputs
	if root == "" {
		root = os.Getenv("BOUNTY_OUTPUTS")
	}
	if root == "" {
		home, _ := os.UserHomeDir()
		root = filepath.Join(home, "tools", "bounty-run", "outputs")
	}
	engine := os.Getenv("BOUNTY_RUN")
	if engine == "" {
		engine = "bounty-run"
	}
	cfg := ui.Config{OutputsRoot: root, EngineBin: engine}
	if _, err := tea.NewProgram(ui.NewRoot(cfg)).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "bounty-tui:", err)
		os.Exit(1)
	}
}

#!/usr/bin/env python3
"""Bounty Runner — recon orchestrator + findings tracker entry point."""
import sys
from pathlib import Path

from runner.cli import main as cli_main
from runner.dashboard import generate as dashboard_generate
from runner.tracker import main as tracker_main

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "track":
        sys.exit(tracker_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "dashboard":
        outputs_root = Path(__file__).resolve().parent / "outputs"
        print(dashboard_generate(outputs_root))
        sys.exit(0)
    sys.exit(cli_main())

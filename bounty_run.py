#!/usr/bin/env python3
"""Bounty Runner — recon orchestrator + findings tracker entry point."""
import sys

from runner.cli import main as cli_main
from runner.tracker import main as tracker_main

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "track":
        sys.exit(tracker_main(sys.argv[2:]))
    sys.exit(cli_main())

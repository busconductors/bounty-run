#!/usr/bin/env python3
"""Bounty Runner — recon orchestrator + findings tracker entry point."""
import sys

from runner import paths
from runner.cli import main as cli_main
from runner.dashboard import generate as dashboard_generate
from runner.introspect import main as introspect_main
from runner.launcher import maybe_exec_tui
from runner.tracker import main as tracker_main

if __name__ == "__main__":
    if paths.is_frozen() and len(sys.argv) > 1 and sys.argv[1] == "_shcheck":
        # Packaged build: the vendored shcheck re-enters this executable.
        import runpy
        script = str(paths.shcheck_script())
        sys.argv = [script] + sys.argv[2:]
        runpy.run_path(script, run_name="__main__")
        sys.exit(0)
    maybe_exec_tui()  # bare `bounty-run` on a terminal → bin/bounty-tui (does not return)
    if len(sys.argv) > 1 and sys.argv[1] == "track":
        sys.exit(tracker_main(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "dashboard":
        outputs_root = paths.data_root()
        print(dashboard_generate(outputs_root))
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] == "introspect":
        # Never reaches the TUI (maybe_exec_tui only fires with no arguments) and
        # a target always contains a dot, so this cannot shadow a valid target.
        sys.exit(introspect_main(sys.argv[2:]))
    sys.exit(cli_main())

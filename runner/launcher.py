"""Bare `bounty-run` (no arguments) opens the TUI instead of the argparse error."""
import os
import sys
from pathlib import Path

DEFAULT_TUI = Path(__file__).resolve().parent.parent / "bin" / "bounty-tui"


def tui_path() -> Path:
    """The TUI binary; $BOUNTY_TUI overrides the bundled bin/bounty-tui."""
    return Path(os.environ.get("BOUNTY_TUI") or DEFAULT_TUI)


def should_launch_tui(argv, interactive: bool) -> bool:
    """Only a bare invocation on a terminal opens the TUI.

    Any argument (target, subcommand, flag such as -h) keeps the CLI path, and a
    non-interactive bare call (pipes, cron, scripts) keeps the old usage error
    so automation never hangs on a full-screen program.
    """
    return len(argv) == 0 and interactive


def maybe_exec_tui(argv=None, interactive=None) -> None:
    """Replace this process with the TUI when appropriate; otherwise return.

    Returns (so the caller falls through to the CLI) when there are arguments,
    no terminal, or the binary is missing — the latter with a hint on stderr.
    """
    argv = sys.argv[1:] if argv is None else argv
    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not should_launch_tui(argv, interactive):
        return
    tui = tui_path()
    if not (tui.is_file() and os.access(tui, os.X_OK)):
        print(f"bounty-run: TUI not built ({tui}); run `make tui` in the repo. "
              "Showing CLI usage instead.", file=sys.stderr)
        return
    os.execv(str(tui), [str(tui)])

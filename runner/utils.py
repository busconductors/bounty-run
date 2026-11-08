"""Shared helpers: subprocess running, logging, tool detection, colorization."""
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path


def _color_enabled() -> bool:
    """True when stdout is a TTY and NO_COLOR is unset."""
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def colorize(text: str, code: str) -> str:
    """Wrap `text` in an ANSI color escape; pass through when color is off."""
    if not _color_enabled():
        return text
    return f"\033[{code}m{text}\033[0m"


SEVERITY_COLOR = {
    "critical": "31",
    "high": "38;5;208",
    "medium": "33",
    "low": "90",
    "info": "34",
    "unknown": "90",
}


def stage_header(num: int, total: int, name: str, width: int = 64) -> None:
    """Print a red-accented, rule-style boxed stage transition header.

    Renders a top rule, a centered ``STAGE n/total - NAME`` line and a closing
    rule.  The accent color is applied via ``colorize`` (itself gated by
    ``_color_enabled``), so piped / redirected output carries no escape codes.
    """
    label = f"STAGE {num}/{total} - {name}"
    rule = "─" * width
    centered = label.center(width)
    print(colorize(rule, "91"), flush=True)
    print(colorize(centered, "1;91"), flush=True)
    print(colorize(rule, "91"), flush=True)


def log(msg: str) -> None:
    print(colorize(f"[+] {msg}", "2"), flush=True)


def warn(msg: str) -> None:
    print(colorize(f"[!] {msg}", "33"), flush=True)


def err(msg: str) -> None:
    print(colorize(f"[-] {msg}", "31"), flush=True)


def have(tool: str) -> bool:
    """True if `tool` is on PATH."""
    return shutil.which(tool) is not None


def run(cmd: str, outfile: str = None, timeout: int = 180) -> str:
    """Run a shell command, return stdout only; surface stderr on failure."""
    log(f"  $ {cmd}")
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            # Kill the entire process group so grandchildren (the actual tool
            # spawned by the shell) don't leak as orphans.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError):
                proc.kill()
            proc.communicate()
            warn(f"  timed out after {timeout}s")
            return ""
    except Exception as e:  # noqa: BLE001
        warn(f"  failed: {e}")
        return ""
    if proc.returncode != 0 and stderr:
        warn(f"  exit {proc.returncode}: {stderr.strip()[:200]}")
    text = stdout or ""
    if outfile:
        p = Path(outfile)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return text

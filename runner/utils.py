"""Shared helpers: subprocess running, logging, tool detection, colorization."""
import os
import shutil
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
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        warn(f"  timed out after {timeout}s")
        return ""
    except Exception as e:  # noqa: BLE001
        warn(f"  failed: {e}")
        return ""
    if r.returncode != 0 and r.stderr:
        warn(f"  exit {r.returncode}: {r.stderr.strip()[:200]}")
    text = r.stdout or ""
    if outfile:
        p = Path(outfile)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return text

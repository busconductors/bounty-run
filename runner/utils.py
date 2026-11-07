"""Shared helpers: subprocess running, logging, tool detection."""
import shutil
import subprocess
from pathlib import Path


def log(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def err(msg: str) -> None:
    print(f"[-] {msg}", flush=True)


def have(tool: str) -> bool:
    """True if `tool` is on PATH."""
    return shutil.which(tool) is not None


def run(cmd: str, outfile: str = None, timeout: int = 180) -> str:
    """Run a shell command, capture output, optionally persist to `outfile`."""
    log(f"  $ {cmd}")
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        warn(f"  timed out after {timeout}s")
        return ""
    except Exception as e:  # noqa: BLE001
        warn(f"  failed: {e}")
        return ""
    text = (r.stdout or "") + "\n" + (r.stderr or "")
    if outfile:
        p = Path(outfile)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return text

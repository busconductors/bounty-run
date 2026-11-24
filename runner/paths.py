"""Filesystem locations that differ between a repo checkout and a frozen build.

Nothing here is resolved at import time: ``BOUNTY_RUN_DATA`` and ``sys.frozen``
are read when the functions are called, so callers and tests can set them.
"""
import os
import shlex
import sys
from pathlib import Path

ENV_DATA = "BOUNTY_RUN_DATA"
_REPO = Path(__file__).resolve().parent.parent


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def data_root() -> Path:
    """Writable data directory: ``$BOUNTY_RUN_DATA`` (empty = unset), else ``<repo>/outputs``."""
    raw = os.environ.get(ENV_DATA, "").strip()
    if raw:
        return Path(os.path.expanduser(raw))
    return _REPO / "outputs"


def resource(rel: str) -> Path:
    """Path to a bundled read-only resource (``assets/...``, ``runner/vendor/...``)."""
    base = Path(getattr(sys, "_MEIPASS", _REPO)) if is_frozen() else _REPO
    return base / rel


def shcheck_script() -> Path:
    return resource("runner/vendor/shcheck.py")


def shcheck_command() -> str:
    """Command prefix that runs the vendored shcheck (frozen: re-enters the executable)."""
    if is_frozen():
        return f"{shlex.quote(sys.executable)} _shcheck"
    return f"python3 {shcheck_script()}"


def child_env(base: dict | None = None) -> dict | None:
    """Environment for external tools, or None (inherit) outside a frozen build.

    The PyInstaller bootloader prepends its bundle dir to ``LD_LIBRARY_PATH`` so
    the frozen interpreter finds its libraries; system tools (curl, nmap, ...)
    must not load those bundled copies. Restore the caller's original value
    (saved as ``LD_LIBRARY_PATH_ORIG``), or drop the variable if there was none.
    """
    if not is_frozen():
        return None
    env = dict(os.environ if base is None else base)
    orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
    if orig is None:
        env.pop("LD_LIBRARY_PATH", None)
    else:
        env["LD_LIBRARY_PATH"] = orig
    return env

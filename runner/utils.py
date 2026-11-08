"""Shared helpers: subprocess running, logging, tool detection, colorization."""
import os
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable

from runner import events


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
    events.log("info", msg)


def warn(msg: str) -> None:
    print(colorize(f"[!] {msg}", "33"), flush=True)
    events.log("warn", msg)


def err(msg: str) -> None:
    print(colorize(f"[-] {msg}", "31"), flush=True)
    events.log("error", msg)


def have(tool: str) -> bool:
    """True if `tool` is on PATH."""
    return shutil.which(tool) is not None


_POLL_S = 0.25        # control-file poll interval while a tool runs
_TERM_GRACE_S = 5     # SIGTERM -> SIGKILL grace on cancel/skip
_JOIN_S = 5           # bounded reader join after a kill


def _tool_name(cmd: str) -> str:
    try:
        argv = shlex.split(cmd)
    except ValueError:
        argv = cmd.split()
    return os.path.basename(argv[0]) if argv else ""


def _pump(stream, sink: list, stream_name: str, stage: str, tool: str,
          on_line: Callable[[str], None] | None) -> None:
    """Drain one pipe line by line: keep raw text, emit events, call on_line."""
    try:
        for raw in stream:
            sink.append(raw)
            line = raw[:-1] if raw.endswith("\n") else raw
            events.output(stage, tool, stream_name, line)
            if on_line is not None:
                try:
                    on_line(line)
                except Exception as e:  # noqa: BLE001
                    warn(f"  on_line failed: {e}")
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _killpg(proc: subprocess.Popen, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except (ProcessLookupError, OSError):
        if proc.poll() is None:
            try:
                proc.send_signal(sig)
            except OSError:
                pass


def _join(readers: list, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    for t in readers:
        t.join(max(0.0, deadline - time.monotonic()))


def run(cmd: str, outfile: str = None, timeout: int = 180,
        on_line: Callable[[str], None] | None = None) -> str:
    """Run a shell command, return stdout only; surface stderr on failure.

    Both pipes are drained line by line on reader threads (each line becomes
    an `output` event; stdout lines also go to `on_line`).  The control file
    is polled every 250 ms; RunCancelled / StageSkipped kill the tool's
    process group and propagate.
    """
    log(f"  $ {cmd}")
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except Exception as e:  # noqa: BLE001
        warn(f"  failed: {e}")
        return ""

    tool = _tool_name(cmd)
    stage = events.current_stage() or ""
    out_raw: list[str] = []
    err_raw: list[str] = []
    readers = [
        threading.Thread(target=_pump, daemon=True,
                         args=(proc.stdout, out_raw, "stdout", stage, tool, on_line)),
        threading.Thread(target=_pump, daemon=True,
                         args=(proc.stderr, err_raw, "stderr", stage, tool, None)),
    ]
    registered = False
    try:
        for t in readers:
            t.start()
        events.register_child(proc.pid)
        registered = True
        deadline = time.monotonic() + timeout
        while True:
            # Done only once the shell exited AND both pipes hit EOF, like
            # communicate(): background grandchildren may still hold a pipe.
            if proc.poll() is not None and not any(t.is_alive() for t in readers):
                break
            events.check_control()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # Kill the entire process group so grandchildren (the actual
                # tool spawned by the shell) don't leak as orphans.
                _killpg(proc, signal.SIGKILL)
                proc.wait()
                _join(readers, _JOIN_S)
                warn(f"  timed out after {timeout}s")
                return ""
            slice_s = min(_POLL_S, remaining)
            if proc.poll() is None:
                try:
                    proc.wait(timeout=slice_s)
                except subprocess.TimeoutExpired:
                    pass
            else:
                alive = [t for t in readers if t.is_alive()]
                if alive:
                    alive[0].join(slice_s)
    except (events.RunCancelled, events.StageSkipped):
        _killpg(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=_TERM_GRACE_S)
        except subprocess.TimeoutExpired:
            pass
        _killpg(proc, signal.SIGKILL)
        proc.wait()
        _join(readers, _JOIN_S)
        raise
    except BaseException as e:
        _killpg(proc, signal.SIGKILL)
        proc.wait()
        _join(readers, _JOIN_S)
        if not isinstance(e, Exception):
            raise
        warn(f"  failed: {e}")
        return ""
    finally:
        if registered:
            events.unregister_child(proc.pid)

    stdout = "".join(out_raw)
    stderr = "".join(err_raw)
    if proc.returncode != 0 and stderr:
        warn(f"  exit {proc.returncode}: {stderr.strip()[:200]}")
    text = stdout
    if outfile:
        p = Path(outfile)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return text

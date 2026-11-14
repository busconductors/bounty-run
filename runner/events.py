"""JSON-lines event stream for monitoring runs (schema v1).

Disabled until init() is called; every emit is then a locked, flushed append.

The stream is bounded per run so it can never grow forever (a single run once
reached 1.46 GB, which made the TUI's from-offset-0 replay lag badly):

* ``init`` starts a fresh file. A non-empty file left by a previous run on the
  same path is rotated to ``<name>.1`` (one generation kept, older dropped).
* ``output`` events (one per tool stdout/stderr line — the only unbounded
  producer) are capped: each line is truncated to ``MAX_OUTPUT_LINE`` chars,
  and once a stage has emitted ``OUTPUT_BUDGET_STAGE`` bytes of output events
  (or the run ``OUTPUT_BUDGET_RUN`` bytes) further output events are dropped
  with a single ``log`` warning. Full tool output still lands in engine.log
  (stdout) and each tool's own artifact files.
* Structural events (run/stage lifecycle, progress, findings, logs) are never
  dropped, so the TUI's stage state stays exact.
"""
import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

_lock = threading.Lock()
_fh = None
_path: Path | None = None
_current_stage: str | None = None
_cancelled = False
_skipped: set[str] = set()
_consume_seq = 0
_skip_reason: str | None = None
_children: set[int] = set()
# In-memory stage timeline (one dict per stage_end), for the run summary. Never
# re-read from events.jsonl, which can reach hundreds of MB.
_stage_log: list[dict] = []

# Output-event bounds (see module docstring). Module attributes so tests can
# shrink them.
MAX_OUTPUT_LINE = 1024 * 1024             # chars kept per output line (TUI contract: 100 KiB lines round-trip)
OUTPUT_BUDGET_STAGE = 16 * 1024 * 1024    # bytes of output events per stage
OUTPUT_BUDGET_RUN = 128 * 1024 * 1024     # bytes of output events per run
_out_bytes_run = 0
_out_bytes_stage: dict[str, int] = {}
_out_capped: set[str] = set()             # stage ids ("" = run-wide) already warned


class RunCancelled(Exception):
    pass


class StageSkipped(Exception):
    pass


def _rotate(path: Path) -> None:
    """Move a non-empty leftover stream aside to ``<name>.1`` (best effort)."""
    try:
        if path.exists() and path.stat().st_size > 0:
            os.replace(path, path.with_name(path.name + ".1"))
    except OSError:
        pass


def init(path: Path) -> None:
    global _fh, _path
    reset()
    _path = Path(path)
    _rotate(_path)
    # "w": every run starts its own stream; nothing is appended across runs.
    _fh = open(_path, "w", buffering=1, encoding="utf-8")


def reset() -> None:
    global _fh, _path, _current_stage, _cancelled, _skip_reason, _out_bytes_run
    with _lock:
        _out_bytes_run = 0
        _out_bytes_stage.clear()
        _out_capped.clear()
        if _fh is not None:
            try:
                _fh.close()
            except OSError:
                pass
        _fh = None
        _path = None
        _current_stage = None
        _cancelled = False
        _skipped.clear()
        _skip_reason = None
        _children.clear()
        _stage_log.clear()


def enabled() -> bool:
    return _fh is not None


def run_dir() -> Path | None:
    return _path.parent if _path is not None else None


def current_stage() -> str | None:
    return _current_stage


def _set_current_stage(stage: str | None) -> None:
    global _current_stage
    _current_stage = stage


def emit(type_: str, **fields) -> None:
    if _fh is None:
        return
    obj = {"v": 1, "t": int(time.time() * 1000), "type": type_, **fields}
    line = json.dumps(obj, ensure_ascii=False) + "\n"
    with _lock:
        if _fh is None:
            return
        _fh.write(line)
        _fh.flush()


def run_start(target: str, flags: dict, stages: list[str]) -> None:
    emit("run_start", target=target, flags=flags, stages=stages)


def stage_start(stage: str) -> None:
    emit("stage_start", stage=stage)


def stage_end(stage: str, status: str, duration_ms: int, counts: dict,
              reason: str | None = None) -> None:
    extra = {} if reason is None else {"reason": reason}
    _stage_log.append({"stage": stage, "status": status, "duration_ms": duration_ms,
                       "counts": dict(counts or {}), "reason": reason})
    emit("stage_end", stage=stage, status=status, duration_ms=duration_ms,
         counts=counts, **extra)


def stage_log() -> list[dict]:
    """The in-memory stage timeline accumulated this run."""
    return list(_stage_log)


def progress(stage: str, done: int, total: int) -> None:
    check_control()
    emit("progress", stage=stage, done=done, total=total)


def log(level: str, msg: str) -> None:
    emit("log", level=level, msg=msg)


def output(stage: str, tool: str, stream: str, line: str) -> None:
    """Emit one tool output line, subject to the per-line and byte budgets."""
    global _out_bytes_run
    if _fh is None:
        return
    if len(line) > MAX_OUTPUT_LINE:
        line = line[:MAX_OUTPUT_LINE] + f" …[+{len(line) - MAX_OUTPUT_LINE} chars]"
    obj = {"v": 1, "t": int(time.time() * 1000), "type": "output",
           "stage": stage, "tool": tool, "stream": stream, "line": line}
    data = json.dumps(obj, ensure_ascii=False) + "\n"
    n = len(data.encode("utf-8"))
    notice = None
    with _lock:
        if _fh is None:
            return
        used = _out_bytes_stage.get(stage, 0)
        if _out_bytes_run + n > OUTPUT_BUDGET_RUN:
            key, what = "", f"run output events capped at {OUTPUT_BUDGET_RUN} bytes"
        elif used + n > OUTPUT_BUDGET_STAGE:
            key, what = stage, (f"stage {stage or '-'} output events capped at "
                                f"{OUTPUT_BUDGET_STAGE} bytes")
        else:
            _out_bytes_stage[stage] = used + n
            _out_bytes_run += n
            _fh.write(data)
            _fh.flush()
            return
        if key in _out_capped:
            return
        _out_capped.add(key)
        notice = what
    log("warn", f"{notice}; further tool output omitted from events "
                "(see engine.log and the tool's output files)")


def finding(severity: str, template: str, host: str, url: str,
            summary: str) -> None:
    emit("finding", severity=severity, template=template, host=host,
         url=url, summary=summary)


def run_end(status: str, totals: dict, report: str, summary: str,
            error: str | None = None) -> None:
    extra = {} if error is None else {"error": error}
    emit("run_end", status=status, totals=totals, report=report,
         summary=summary, **extra)


def _pid_start() -> int:
    stat = Path("/proc/self/stat").read_text()
    return int(stat.rsplit(")", 1)[1].split()[19])


def write_run_json(target: str, flags: dict, version: str) -> None:
    d = run_dir()
    if d is None:
        return
    data = {
        "pid": os.getpid(),
        "pgid": os.getpgrp(),
        "pid_start": _pid_start(),
        "target": target,
        "flags": flags,
        "started": int(time.time() * 1000),
        "engine_version": version,
    }
    (d / "run.json").write_text(json.dumps(data, ensure_ascii=False))


def check_control() -> None:
    """Poll the control file; raise RunCancelled / StageSkipped (sticky)."""
    global _cancelled
    d = run_dir()
    if d is None:
        return
    with _lock:
        global _consume_seq
        _consume_seq += 1
        mine = d / f".control.consumed.{os.getpid()}.{_consume_seq}"
        try:
            # Atomic claim: a concurrent writer's rename lands on a fresh
            # "control", never on content we have already read.
            os.replace(d / "control", mine)
        except OSError:
            mine = None
        if mine is not None:
            try:
                text = mine.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            try:
                mine.unlink()
            except OSError:
                pass
            for ln in text.splitlines():
                parts = ln.split()
                if parts == ["cancel"]:
                    _cancelled = True
                elif len(parts) == 2 and parts[0] == "skip":
                    _skipped.add(parts[1])
        cancelled = _cancelled
        skipped = _current_stage in _skipped
    if cancelled:
        raise RunCancelled()
    if skipped:
        raise StageSkipped(_current_stage)


def _write_pids_locked() -> None:
    d = run_dir()
    if d is None:
        return
    tmp = d / "pids.tmp"
    tmp.write_text("".join("%d\n" % p for p in sorted(_children)))
    os.replace(tmp, d / "pids")


def register_child(pgid: int) -> None:
    with _lock:
        _children.add(pgid)
        _write_pids_locked()


def unregister_child(pgid: int) -> None:
    with _lock:
        _children.discard(pgid)
        _write_pids_locked()


def mark_skipped(reason: str) -> None:
    global _skip_reason
    _skip_reason = reason


@dataclass
class StageCtx:
    stage: str
    counts: dict = field(default_factory=dict)


@contextmanager
def stage(stage_id: str) -> Iterator[StageCtx]:
    """Wrap one pipeline stage: stage_start on entry, stage_end on exit.

    StageSkipped is suppressed (status ``skipped``) so the pipeline continues;
    RunCancelled (``cancelled``) and any other exception (``failed``) re-raise.
    A ``mark_skipped`` reason set inside the stage turns ``ok`` into
    ``skipped``.  When events are disabled this is a plain no-op.
    """
    global _skip_reason
    ctx = StageCtx(stage_id)
    if not enabled():
        yield ctx
        return
    _skip_reason = None
    _set_current_stage(stage_id)
    stage_start(stage_id)
    t0 = time.monotonic()
    status = "ok"
    try:
        try:
            # Honour a cancel already pending before any stage work starts.
            # A skip for this stage is sticky, so the body's first checkpoint
            # re-raises it (a generator context manager cannot skip its body).
            check_control()
        except StageSkipped:
            pass
        yield ctx
    except StageSkipped:
        status = "skipped"
    except RunCancelled:
        status = "cancelled"
        raise
    except BaseException:
        status = "failed"
        raise
    finally:
        reason = _skip_reason
        if status == "ok" and reason is not None:
            status = "skipped"
        stage_end(stage_id, status, int((time.monotonic() - t0) * 1000),
                  ctx.counts, reason if status == "skipped" else None)
        _skip_reason = None
        _set_current_stage(None)

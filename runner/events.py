"""JSON-lines event stream for monitoring runs (schema v1).

Disabled until init() is called; every emit is then a locked, flushed append.
"""
import json
import os
import threading
import time
from pathlib import Path

_lock = threading.Lock()
_fh = None
_path: Path | None = None
_current_stage: str | None = None


def init(path: Path) -> None:
    global _fh, _path
    reset()
    _path = Path(path)
    _fh = open(_path, "a", buffering=1, encoding="utf-8")


def reset() -> None:
    global _fh, _path, _current_stage
    with _lock:
        if _fh is not None:
            try:
                _fh.close()
            except OSError:
                pass
        _fh = None
        _path = None
        _current_stage = None


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
    emit("stage_end", stage=stage, status=status, duration_ms=duration_ms,
         counts=counts, **extra)


def progress(stage: str, done: int, total: int) -> None:
    emit("progress", stage=stage, done=done, total=total)


def log(level: str, msg: str) -> None:
    emit("log", level=level, msg=msg)


def output(stage: str, tool: str, stream: str, line: str) -> None:
    emit("output", stage=stage, tool=tool, stream=stream, line=line)


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

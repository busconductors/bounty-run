"""Drive one of every event type through the real runner.events emitter.

Used by the Go contract test (tui/internal/events/contract_test.go).
Usage: fake_run.py <events.jsonl path>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from runner import events  # noqa: E402


def main(path: str) -> None:
    events.init(Path(path))
    events.run_start("a.example.com", {"amass": True, "timeout": 30, "x": None},
                     ["live", "nuclei"])
    events.stage_start("nuclei")
    events._set_current_stage("nuclei")
    events.progress("nuclei", 1, 2)
    events.log("info", "héllo wörld ✓")
    events.output("nuclei", "nuclei", "stdout", "x" * (100 * 1024))
    events.finding("high", "admin-panel", "a.example.com",
                   "https://a.example.com/admin", "Exposed admin panel")
    events.stage_end("nuclei", "ok", 1234, {"hosts": 3})
    events.run_end("ok", {"findings": 1, "hosts": 3}, "/tmp/run/report.md",
                   "/tmp/run/summary.md")
    events.reset()


if __name__ == "__main__":
    main(sys.argv[1])

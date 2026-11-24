"""events v1 contract: contract/events.v1.schema.json vs. what the engine emits.

The Go client checks the same schema in core/events/schema_test.go. The
validator below is deliberately tiny and test-only: it supports just the
JSON Schema keywords the schema uses (no third-party dependency).
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from runner import events  # noqa: E402

CONTRACT = ROOT / "contract"
SCHEMA = json.loads((CONTRACT / "events.v1.schema.json").read_text())
FAKE_RUN = ROOT / "tests" / "fixtures" / "fake_run.py"
TUI_TESTDATA = ROOT / "tui" / "internal" / "ui" / "testdata"

EIGHT = ["run_start", "stage_start", "stage_end", "progress", "log", "output",
         "finding", "run_end"]
# Required fields per type, pinned here so that loosening the schema fails.
REQUIRED = {
    "run_start": ["target", "flags", "stages"],
    "stage_start": ["stage"],
    "stage_end": ["stage", "status", "duration_ms", "counts"],
    "progress": ["stage", "done", "total"],
    "log": ["level", "msg"],
    "output": ["stage", "tool", "stream", "line"],
    "finding": ["severity", "template", "host", "url", "summary"],
    "run_end": ["status", "totals", "report", "summary"],
}
COMMON = ["v", "t", "type"]


def _resolve(ref):
    node = SCHEMA
    for part in ref.removeprefix("#/").split("/"):
        node = node[part]
    return node


def errors(value, schema, path="$"):
    """Return a list of violations of `schema` by `value`."""
    if "$ref" in schema:
        return errors(value, _resolve(schema["$ref"]), path)
    if "oneOf" in schema:
        ok = [s for s in schema["oneOf"] if not errors(value, s, path)]
        return [] if len(ok) == 1 else [f"{path}: matches {len(ok)} of oneOf"]
    out = []
    if "const" in schema and (value != schema["const"] or isinstance(value, bool)):
        out.append(f"{path}: want const {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{path}: {value!r} not in enum")
    if "type" in schema:
        py = {"object": dict, "array": list, "string": str, "integer": int}[schema["type"]]
        if not isinstance(value, py) or isinstance(value, bool):
            return out + [f"{path}: not {schema['type']}"]
    if "minimum" in schema and isinstance(value, int) and value < schema["minimum"]:
        out.append(f"{path}: below minimum")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for k in schema.get("required", []):
            if k not in value:
                out.append(f"{path}: missing {k}")
        extra = schema.get("additionalProperties", True)
        for k, v in value.items():
            if k in props:
                out += errors(v, props[k], f"{path}.{k}")
            elif extra is False:
                out.append(f"{path}: unexpected {k}")
            elif isinstance(extra, dict):
                out += errors(v, extra, f"{path}.{k}")
    if isinstance(value, list) and "items" in schema:
        for i, v in enumerate(value):
            out += errors(v, schema["items"], f"{path}[{i}]")
    return out


def run_fake(path):
    subprocess.run([sys.executable, str(FAKE_RUN), str(path)], check=True, cwd=ROOT)
    return [json.loads(ln) for ln in Path(path).read_text().splitlines()]


class TestEventContract(unittest.TestCase):
    def setUp(self):
        events.reset()
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        events.reset()
        self._td.cleanup()

    def test_fake_run_validates_against_schema(self):
        evs = run_fake(self.tmp / "events.jsonl")
        self.assertEqual({e["type"] for e in evs}, set(EIGHT))
        for e in evs:
            self.assertEqual(errors(e, SCHEMA), [], e["type"])

    def test_optional_fields_validate(self):
        events.init(self.tmp / "events.jsonl")
        events.stage_end("nuclei", "skipped", 5, {}, reason="user skip")
        events.run_end("failed", {"high": 0}, "r.md", "s.md", error="boom")
        events.reset()
        evs = [json.loads(ln) for ln in (self.tmp / "events.jsonl").read_text().splitlines()]
        self.assertEqual([e["type"] for e in evs], ["stage_end", "run_end"])
        self.assertEqual(evs[0]["reason"], "user skip")
        self.assertEqual(evs[1]["error"], "boom")
        for e in evs:
            self.assertEqual(errors(e, SCHEMA), [])

    def test_schema_covers_all_eight_types(self):
        defs = SCHEMA["$defs"]
        self.assertEqual(sorted(defs), sorted(EIGHT))
        self.assertEqual(len(SCHEMA["oneOf"]), 8)
        for name, d in defs.items():
            self.assertEqual(d["properties"]["type"], {"const": name})
            self.assertEqual(d["required"], COMMON + REQUIRED[name], name)
            self.assertFalse(d["additionalProperties"])

    def test_schema_rejects_bad_events(self):
        good = {"v": 1, "t": 1, "type": "stage_start", "stage": "subs"}
        self.assertEqual(errors(good, SCHEMA), [])
        for bad in ({**good, "v": 2}, {**good, "extra": 1},
                    {k: v for k, v in good.items() if k != "stage"},
                    {**good, "type": "nope"}):
            self.assertNotEqual(errors(bad, SCHEMA), [])

    def test_capped_output_warning_is_a_log_event(self):
        saved = events.OUTPUT_BUDGET_STAGE
        events.OUTPUT_BUDGET_STAGE = 600
        try:
            events.init(self.tmp / "events.jsonl")
            for i in range(20):
                events.output("vuln", "nuclei", "stdout", f"example.com line {i}")
            events.reset()
        finally:
            events.OUTPUT_BUDGET_STAGE = saved
        evs = [json.loads(ln) for ln in (self.tmp / "events.jsonl").read_text().splitlines()]
        warns = [e for e in evs if e["type"] == "log"]
        self.assertEqual(len(warns), 1)
        self.assertEqual(warns[0]["level"], "warn")
        self.assertIn("capped", warns[0]["msg"])
        self.assertNotIn("stage", warns[0])
        for e in evs:
            self.assertEqual(errors(e, SCHEMA), [])

    def test_golden_fixtures_validate(self):
        for p in [*sorted(CONTRACT.glob("testdata/*.jsonl")), TUI_TESTDATA / "full_run.jsonl"]:
            lines = p.read_text().split("\n")
            complete = lines[:-1]  # the final element has no newline after it
            for ln in complete:
                self.assertEqual(errors(json.loads(ln), SCHEMA), [], f"{p.name}: {ln[:80]}")
        capped = [json.loads(ln) for ln in
                  (CONTRACT / "testdata" / "capped_output.jsonl").read_text().splitlines()]
        self.assertTrue(any(e["type"] == "log" and e["level"] == "warn" for e in capped))
        partial = (CONTRACT / "testdata" / "partial_line.jsonl").read_text()
        self.assertFalse(partial.endswith("\n"))
        with self.assertRaises(ValueError):
            json.loads(partial.rsplit("\n", 1)[1])


if __name__ == "__main__":
    unittest.main()

"""Regression tests for the engine memory balloon (stage 13 OOM).

Root cause recap (see commit body): on a large target the engine held the full
stdout of streaming tools in RAM even though each line was already streamed
(`on_line`) and persisted to disk (`nuclei -o`, katana JSONL), and it re-read the
whole ``nuclei.jsonl`` via ``read_text().split()``. These tests fail if any of
those unbounded in-memory copies comes back.

Stdlib unittest only:

    cd ~/tools/bounty-run && python3 -m unittest tests.test_memory_bounds -v
"""
import io
import json
import sys
import tracemalloc
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import stages, utils  # noqa: E402


class RunCaptureTest(unittest.TestCase):
    """utils.run(capture=False) must stream without buffering the full stdout."""

    def test_capture_false_streams_but_keeps_nothing(self):
        got = []
        # Emit many large lines; a streaming consumer keeps only a count.
        n_lines, line_len = 20_000, 1000
        cmd = (f"python3 -c \"import sys;"
               f"[sys.stdout.write('x'*{line_len}+chr(10)) for _ in range({n_lines})]\"")
        with redirect_stdout(io.StringIO()):
            out = utils.run(cmd, timeout=60, on_line=lambda _line: got.append(1),
                            capture=False)
        # Every line was still delivered to on_line (streaming intact)...
        self.assertEqual(len(got), n_lines)
        # ...but the aggregate stdout was NOT retained in RAM.
        self.assertEqual(out, "")

    def test_capture_false_does_not_balloon(self):
        """Peak Python-tracked memory stays a small fraction of total output."""
        n_lines, line_len = 50_000, 1000
        total_bytes = n_lines * line_len
        cmd = (f"python3 -c \"import sys;"
               f"[sys.stdout.write('x'*{line_len}+chr(10)) for _ in range({n_lines})]\"")
        tracemalloc.start()
        base, _ = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        with redirect_stdout(io.StringIO()):
            utils.run(cmd, timeout=60, on_line=lambda _line: None, capture=False)
        _cur, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        # Measure the DELTA above the baseline (tracemalloc peak is absolute, so
        # it includes whatever the test runner already holds live).
        grew = peak - base
        # If out_raw buffered everything, growth would approach total_bytes
        # (~50 MB). Streaming keeps it to a tiny working set; allow 1/10th.
        self.assertLess(grew, total_bytes // 10,
                        f"grew {grew} bytes ~ full output {total_bytes}: stdout is "
                        f"being buffered in memory instead of streamed")

    def test_capture_true_is_unchanged_default(self):
        """Default (capture=True) still returns the full stdout, byte for byte."""
        with redirect_stdout(io.StringIO()):
            self.assertEqual(utils.run("printf 'a\\nb\\n'"), "a\nb\n")


class ParseNucleiStreamingTest(unittest.TestCase):
    """_parse_nuclei_jsonl must stream the file, never load it wholesale."""

    def _write_jsonl(self, path, n, pad=0):
        obj = {"template-id": "t", "info": {"severity": "info", "name": "n"},
               "matched-at": "https://h/x", "host": "h"}
        if pad:
            # A large field nuclei emits (e.g. request/response capture) that we
            # do NOT keep in the finding dict: it bloats the FILE but not the
            # parsed result, so a wholesale read spikes while streaming does not.
            obj["request"] = "q" * pad
        line = json.dumps(obj)
        with open(path, "w") as fh:
            for _ in range(n):
                fh.write(line + "\n")

    def test_does_not_call_read_text(self):
        """A whole-file read is the balloon; prove parsing never uses it.

        read_text() is monkeypatched to blow up — a streaming parser is immune,
        a ``read_text().split()`` parser would raise.
        """
        with TemporaryDirectory() as d:
            p = Path(d) / "nuclei.jsonl"
            self._write_jsonl(p, 100)
            orig = Path.read_text

            def boom(self, *a, **k):
                raise AssertionError("_parse_nuclei_jsonl must not read the whole "
                                     "file into memory")
            Path.read_text = boom
            try:
                findings = stages._parse_nuclei_jsonl(p)
            finally:
                Path.read_text = orig
        self.assertEqual(len(findings), 100)
        self.assertEqual(findings[0]["template"], "t")

    def test_peak_memory_well_under_file_size(self):
        """Parsing a big file must not spike to a multiple of its size.

        Each line carries a large field that is NOT kept in the finding dict, so
        the parsed result stays small while the file is large. A streaming parser
        holds only one line + the small result; a ``read_text().split()`` parser
        holds the whole file string plus a list of every line.
        """
        # Large per-line padding (kept in the FILE, dropped from the finding
        # dict) so the file dwarfs the legitimate result list — a wide margin
        # between streaming (small working set) and a wholesale read.
        with TemporaryDirectory() as d:
            p = Path(d) / "nuclei.jsonl"
            self._write_jsonl(p, 20_000, pad=2000)
            file_size = p.stat().st_size
            tracemalloc.start()
            base, _ = tracemalloc.get_traced_memory()
            tracemalloc.reset_peak()
            findings = stages._parse_nuclei_jsonl(p)
            _cur, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
        self.assertEqual(len(findings), 20_000)
        # DELTA above baseline (tracemalloc peak is absolute). Streaming growth is
        # the small result list + one line (~a few MB); a wholesale read would
        # spike to ~2-3x the file. file_size // 3 sits well above the former and
        # well below the latter.
        grew = peak - base
        self.assertLess(grew, file_size // 3,
                        f"parse grew {grew} ~ file {file_size}: the file is being "
                        f"loaded wholesale, not streamed")


if __name__ == "__main__":
    unittest.main(verbosity=2)

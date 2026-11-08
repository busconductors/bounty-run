"""Unit tests for runner.banner + utils colorization.

Pure functions only — no network, no external tools. Run with stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_banner.py -v
"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import utils  # noqa: E402
from runner import banner  # noqa: E402


class TestBannerRender(unittest.TestCase):
    def test_render_returns_literal_fallback_when_asset_missing(self):
        # Make Path.read_text raise so render() takes its missing-asset branch.
        orig = Path.read_text

        def _boom(self, *args, **kwargs):
            raise FileNotFoundError("nope")

        Path.read_text = _boom
        self.addCleanup(setattr, Path, "read_text", orig)
        self.assertEqual(banner.render(), "BuntyRun by Strasser Lab")

    def test_render_returns_non_empty_with_real_asset(self):
        out = banner.render()
        self.assertIsInstance(out, str)
        self.assertNotEqual(out, "")

    def test_render_uses_red_glyph_color_when_color_enabled(self):
        # With color forced on, '#' art glyphs are wrapped in the red SGR code.
        orig = utils._color_enabled
        utils._color_enabled = lambda: True
        self.addCleanup(setattr, utils, "_color_enabled", orig)
        out = banner.render()
        self.assertIn("\033[91m#\033[0m", out)
        # Bright cyan must no longer be used for the art glyphs.
        self.assertNotIn("\033[96m#\033[0m", out)

    def test_print_banner_renders_without_error(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            banner.print_banner()
        self.assertNotEqual(buf.getvalue(), "")


class TestStageHeader(unittest.TestCase):
    def test_stage_header_renders_without_error(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            utils.stage_header(5, 15, "VULNERABILITY SCAN (NUCLEI)")
        out = buf.getvalue()
        self.assertIn("STAGE 5/15 - VULNERABILITY SCAN (NUCLEI)", out)
        # Three lines: top rule, label, bottom rule.
        self.assertEqual(len([ln for ln in out.splitlines() if ln.strip()]), 3)

    def test_stage_header_is_plain_when_color_disabled(self):
        orig = utils._color_enabled
        utils._color_enabled = lambda: False
        self.addCleanup(setattr, utils, "_color_enabled", orig)
        buf = io.StringIO()
        with redirect_stdout(buf):
            utils.stage_header(1, 15, "SUBDOMAIN ENUMERATION")
        self.assertNotIn("\033[", buf.getvalue())


class TestColorize(unittest.TestCase):
    def test_colorize_returns_text_unchanged_when_no_color_set(self):
        old = os.environ.get("NO_COLOR")
        os.environ["NO_COLOR"] = "1"
        try:
            self.assertEqual(utils.colorize("hello", "31"), "hello")
        finally:
            if old is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = old

    def test_colorize_wraps_text_when_color_enabled(self):
        orig = utils._color_enabled
        utils._color_enabled = lambda: True
        self.addCleanup(setattr, utils, "_color_enabled", orig)
        self.assertEqual(utils.colorize("hi", "31"), "\033[31mhi\033[0m")

    def test_color_enabled_is_false_when_no_color_set(self):
        old = os.environ.get("NO_COLOR")
        os.environ["NO_COLOR"] = "1"
        try:
            self.assertFalse(utils._color_enabled())
        finally:
            if old is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = old


class TestSeverityColorMap(unittest.TestCase):
    def test_severity_color_has_six_keys(self):
        self.assertEqual(
            set(utils.SEVERITY_COLOR),
            {"critical", "high", "medium", "low", "info", "unknown"},
        )
        self.assertEqual(len(utils.SEVERITY_COLOR), 6)

    def test_severity_color_values(self):
        self.assertEqual(utils.SEVERITY_COLOR["critical"], "31")
        self.assertEqual(utils.SEVERITY_COLOR["high"], "38;5;208")
        self.assertEqual(utils.SEVERITY_COLOR["medium"], "33")
        self.assertEqual(utils.SEVERITY_COLOR["low"], "90")
        self.assertEqual(utils.SEVERITY_COLOR["info"], "34")
        self.assertEqual(utils.SEVERITY_COLOR["unknown"], "90")


if __name__ == "__main__":
    unittest.main(verbosity=2)

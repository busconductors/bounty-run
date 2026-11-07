"""Unit tests for runner.banner + utils colorization.

Pure functions only — no network, no external tools. Run with stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_banner.py -v
"""
import os
import sys
import unittest
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

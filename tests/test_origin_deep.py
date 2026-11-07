"""Unit tests for runner.origin_deep (crt.sh deep origin discovery).

Hermetic — no network, no external tools, no DNS. Run with stdlib unittest:

    cd ~/tools/bounty-run && python3 -m unittest discover -s tests -v
    # or directly:
    python3 tests/test_origin_deep.py -v
"""
import ipaddress
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Make the project root importable regardless of cwd / how the test is invoked.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from runner import origin_deep, stages, utils  # noqa: E402


def crt_json(entries):
    """Serialize a list of crt.sh-style items (each with a name_value string)."""
    return json.dumps(entries)


# A crt.sh payload with wildcards, dupes, out-of-scope names and mixed SANs.
FAKE_CRT = crt_json([
    {"name_value": "*.example.com\nexample.com"},
    {"name_value": "www.example.com\nmail.example.com"},
    {"name_value": "dev.example.com\nother.example.com\nunrelated.org"},
    {"name_value": "*.example.com\nmail.example.com"},          # dupes
    {"name_value": "not-example.org\nwww.not-example.org"},      # out of scope
    {"name_value": ""},                                          # empty SAN
    {"name_value": None},                                        # non-string SAN
])

# Fake resolution: Cloudflare edge IPs live in 1.2.3.0/24.
RESOLVE_MAP = {
    "example.com": "1.2.3.4",       # CF edge
    "www.example.com": "1.2.3.5",   # CF edge
    "mail.example.com": "5.6.7.8",  # real origin
    "dev.example.com": "5.6.7.8",   # same origin (dedupes into one IP)
    "other.example.com": "9.9.9.10",
}
CF_RANGES = [ipaddress.ip_network("1.2.3.0/24")]


def fake_run(cmd, outfile=None, timeout=180):
    """Dispatch on the command: crt.sh -> canned JSON, verify -> 200|ip."""
    if "crt.sh" in cmd:
        return FAKE_CRT
    if "--resolve" in cmd:
        m = re.search(r"--resolve\s+\S+:443:(\S+)", cmd)
        ip = m.group(1) if m else "1.1.1.1"
        return f"200|{ip}"
    return ""


class OriginDeepTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.outdir = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.target = "example.com"

    # --- helpers ---------------------------------------------------------

    def patch_happy_path(self):
        """Patch run/_resolve/_cloudflare_ranges for a full crt.sh round trip."""
        p1 = mock.patch.object(utils, "run", side_effect=fake_run)
        p2 = mock.patch.object(stages, "_resolve", side_effect=lambda h: RESOLVE_MAP.get(h, ""))
        p3 = mock.patch.object(stages, "_cloudflare_ranges", return_value=list(CF_RANGES))
        return p1, p2, p3

    # --- tests -----------------------------------------------------------

    def test_happy_path_returns_rows_with_sources_and_status(self):
        with mock.patch.object(utils, "run", side_effect=fake_run), \
             mock.patch.object(stages, "_resolve", side_effect=lambda h: RESOLVE_MAP.get(h, "")), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=list(CF_RANGES)):
            rows = origin_deep.origin_deep(self.target, self.outdir, {})

        ips = sorted(r["ip"] for r in rows)
        self.assertEqual(ips, ["5.6.7.8", "9.9.9.10"])
        by_ip = {r["ip"]: r for r in rows}
        self.assertEqual(sorted(by_ip["5.6.7.8"]["sources"]),
                         ["dev.example.com", "mail.example.com"])
        self.assertEqual(by_ip["9.9.9.10"]["sources"], ["other.example.com"])
        for r in rows:
            self.assertEqual(r["status"], "200")
            self.assertEqual(r["remote_ip"], r["ip"])
            self.assertEqual(set(r), {"ip", "sources", "status", "remote_ip"})

    def test_cloudflare_ips_are_filtered_out(self):
        with mock.patch.object(utils, "run", side_effect=fake_run), \
             mock.patch.object(stages, "_resolve", side_effect=lambda h: RESOLVE_MAP.get(h, "")), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=list(CF_RANGES)):
            rows = origin_deep.origin_deep(self.target, self.outdir, {})

        ips = {r["ip"] for r in rows}
        # 1.2.3.4 / 1.2.3.5 resolve into the fake CF range and must not appear.
        self.assertNotIn("1.2.3.4", ips)
        self.assertNotIn("1.2.3.5", ips)

    def test_duplicate_sans_collapse_into_one_ip_with_multiple_sources(self):
        with mock.patch.object(utils, "run", side_effect=fake_run), \
             mock.patch.object(stages, "_resolve", side_effect=lambda h: RESOLVE_MAP.get(h, "")), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=list(CF_RANGES)):
            rows = origin_deep.origin_deep(self.target, self.outdir, {})

        self.assertEqual(len(rows), 2)
        origin = next(r for r in rows if r["ip"] == "5.6.7.8")
        self.assertEqual(len(origin["sources"]), 2)

    def test_writes_origin_deep_txt(self):
        with mock.patch.object(utils, "run", side_effect=fake_run), \
             mock.patch.object(stages, "_resolve", side_effect=lambda h: RESOLVE_MAP.get(h, "")), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=list(CF_RANGES)):
            origin_deep.origin_deep(self.target, self.outdir, {})

        outfile = self.outdir / "origin_deep.txt"
        self.assertTrue(outfile.exists())
        lines = outfile.read_text().splitlines()
        self.assertEqual(len(lines), 2)
        # Format: ip \t status \t sources
        self.assertIn("5.6.7.8\t200\tdev.example.com,mail.example.com", lines)
        self.assertIn("9.9.9.10\t200\tother.example.com", lines)

    def test_empty_crtsh_body_returns_empty(self):
        with mock.patch.object(utils, "run", return_value=""):
            rows = origin_deep.origin_deep(self.target, self.outdir, {})
        self.assertEqual(rows, [])

    def test_invalid_json_returns_empty(self):
        with mock.patch.object(utils, "run", return_value="<html>not json</html>"):
            rows = origin_deep.origin_deep(self.target, self.outdir, {})
        self.assertEqual(rows, [])

    def test_empty_cloudflare_ranges_returns_empty_and_warns(self):
        with mock.patch.object(utils, "run", side_effect=fake_run), \
             mock.patch.object(stages, "_resolve", side_effect=lambda h: RESOLVE_MAP.get(h, "")), \
             mock.patch.object(stages, "_cloudflare_ranges", return_value=[]), \
             mock.patch.object(utils, "warn") as warn:
            rows = origin_deep.origin_deep(self.target, self.outdir, {})
        self.assertEqual(rows, [])
        self.assertTrue(any("Cloudflare ranges" in c.args[0] for c in warn.call_args_list))

    def test_non_list_payload_returns_empty(self):
        with mock.patch.object(utils, "run", return_value=json.dumps({"oops": True})):
            rows = origin_deep.origin_deep(self.target, self.outdir, {})
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
